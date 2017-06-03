/*
Copyright (C) 2017 The University of Notre Dame
This software is distributed under the GNU General Public License.
See the file LICENSE for details.
*/

#include "kerneltypes.h"
#include "ata.h"
#include "kmalloc.h"
#include "fs.h"
#include "fdtable.h"
#include "string.h"
#include "hashtable.h"

static uint32_t ceiling(double d) {
    uint32_t i = (uint32_t) d;
    if (d == (double) i)
	    return i;
    return i + 1;
}

static struct fs_superblock s;
static struct fdtable table;
static uint32_t cwd;
static struct fs_commit_list commits = {0};
static struct hash_set *reserved_bits;

static void fs_print_superblock(struct fs_superblock s) {
	printf("fs: magic: %u, blocksize: %u, free_blocks: %u, inode_count: %u, inode_bitmap_start: %u, inode_start: %u, block_bitmap_start: %u, free_block_start: %u \n",
			s.magic,
			s.blocksize,
			s.num_free_blocks,
			s.num_inodes,
			s.inode_bitmap_start,
			s.inode_start,
			s.block_bitmap_start,
			s.free_block_start);
}

static void fs_print_inode(struct fs_inode *n) {
	uint32_t i;
	printf("fs: inode_number: %u, is_directory: %u, sz: %u, direct_addresses_len: %u\n",
			n->inode_number,
			n->is_directory,
			n->sz,
			n->direct_addresses_len);
	for (i = 0; i < n->direct_addresses_len; i++)
		printf("fs: direct_addresses[%u]: %u\n", i, n->direct_addresses[i]);
}

static void fs_print_dir_record(struct fs_dir_record *d) {
	printf("fs: filename: %s, inode_number: %u, offset: %d\n",
			d->filename,
			d->inode_number,
			d->offset_to_next);
}

static void fs_print_dir_record_list(struct fs_dir_record_list *l) {
	uint32_t i;
	for (i = 0; i < l->list_len; i++) {
		fs_print_dir_record(l->list + i);
	}
}

static void fs_print_commit(struct fs_commit_list_entry *entry) {
	char *opstring, *datastring;
	switch (entry->data_type) {
		case FS_COMMIT_INODE:
			datastring = "inode";
			break;
		case FS_COMMIT_BLOCK:
			datastring= "data block";
			break;
	}
	switch (entry->op) {
		case FS_COMMIT_CREATE:
			opstring = "create";
			break;
		case FS_COMMIT_MODIFY:
			opstring = "modify";
			break;
		case FS_COMMIT_DELETE:
			opstring = "delete";
			break;
	}
	printf("fs: op: %s, data: %s, number: %u\n", opstring, datastring, entry->number);
	if (entry->data_type == FS_COMMIT_INODE){
		fs_print_inode(entry->data.node);
	}
}

static void fs_print_commit_list() {
	struct fs_commit_list_entry *start = commits.head;
	printf("fs: commit list:\n");
	while (start) {
		fs_print_commit(start);
		start = start->next;
	}
}

static int set_bit(uint32_t index, uint32_t begin, uint32_t end){
	uint8_t bit_buffer[FS_BLOCKSIZE];
	uint32_t bit_block_index = index / (8 * FS_BLOCKSIZE);
	uint32_t bit_block_offset = index % (8 * FS_BLOCKSIZE);
	uint8_t bit_mask = 1u << (7 - bit_block_offset % 8);

	uint32_t key_for_hash = begin * FS_BLOCKSIZE + index;
	if(hash_set_delete(reserved_bits, key_for_hash)){
		return -1;
	}

	ata_read(0, bit_buffer, 1, begin + bit_block_index);
	if ((bit_mask & bit_buffer[bit_block_offset / 8]) > 0)
		return -1;

	bit_buffer[bit_block_offset / 8] |= bit_mask;
	ata_write(0, bit_buffer, 1, begin + bit_block_index);

	return 0;
}

static int unset_bit(uint32_t index, uint32_t begin, uint32_t end){
	uint8_t bit_buffer[FS_BLOCKSIZE];
	uint32_t bit_block_index = index / (8 * FS_BLOCKSIZE);
	uint32_t bit_block_offset = index % (8 * FS_BLOCKSIZE);
	uint8_t bit_mask = 1u << (7 - bit_block_offset % 8);

	ata_read(0, bit_buffer, 1, begin + bit_block_index);

	if ((bit_mask & bit_buffer[bit_block_offset / 8]) == 0) {
		return -1;
	}

	bit_buffer[bit_block_offset / 8] ^= bit_mask;
	ata_write(0, bit_buffer, 1, begin + bit_block_index);

	return 0;
}

static int check_bit(uint32_t index, uint32_t begin, uint32_t end, bool *res){
	uint8_t bit_buffer[FS_BLOCKSIZE];
	uint32_t bit_block_index = index / (8 * FS_BLOCKSIZE);
	uint32_t bit_block_offset = index % (8 * FS_BLOCKSIZE);
	uint8_t bit_mask = 1u << (7 - bit_block_offset % 8);

	uint32_t key_for_hash = begin * FS_BLOCKSIZE + index;
	*res = hash_set_lookup(reserved_bits, key_for_hash);
	if (*res) {
		return 0;
	}

	ata_read(0, bit_buffer, 1, begin + bit_block_index);
	*res = (bit_mask & bit_buffer[bit_block_offset / 8]) != 0;

	return 0;
}

static int fs_read_block_raw(uint32_t index, uint8_t *buffer, uint32_t blocks) {
	ata_read(0, buffer, 1, index);
	return 0;
}

static int fs_get_available_bit(uint32_t index, uint32_t *res) {
	uint32_t bit_index;
	uint8_t bit_buffer[FS_BLOCKSIZE];
	fs_read_block_raw(index, bit_buffer, 1);

	for (bit_index = 0; bit_index < sizeof(bit_buffer); bit_index++) {
		if (bit_buffer[bit_index] != 255) {
			uint8_t bit = (1u << 7);
			uint32_t offset;
			for (offset = 0; offset < sizeof(uint8_t) * 8; offset += 1) {
				uint32_t potential_result;
				if (!(bit_buffer[bit_index] & bit)) {
					potential_result = index * FS_BLOCKSIZE + bit_index * sizeof(uint8_t) * 8 + offset;
					if(hash_set_add(reserved_bits, potential_result) == 0) {
						*res = potential_result;
						return 0;
					}
				}
				bit >>= 1;
			}
		}
	}
	return -1;
}

static int fs_ffs_bitmap_range(uint32_t start, uint32_t end, uint32_t *res) {
	uint32_t index;
	int result;

	for (index = start; index < end; index++) {
		result = fs_get_available_bit(index, res);
		if (result == 0) {
			*res -= start * FS_BLOCKSIZE;
			return 0;
		}
	}
	return -1;
}

static int fs_get_available_block(uint32_t *res) {
	return fs_ffs_bitmap_range(s.block_bitmap_start, s.free_block_start, res);
}

static int fs_get_available_inode(uint32_t *res) {
	int ret = fs_ffs_bitmap_range(s.inode_bitmap_start, s.inode_start, res);
	*res += 1;
	return ret;
}

static int fs_check_format(void) {

	uint8_t buffer[FS_BLOCKSIZE];
	ata_read(0, buffer, 1, 0);
	memcpy(&s, buffer, sizeof(s));
	if (s.magic == FS_MAGIC) {
		printf("fs: fs already initialized on id 0\n");
		fs_print_superblock(s);
		return 1;
	}
	return 0;
}

static int fs_init_commit_list() {
	struct fs_commit_list_entry *current = commits.head, *next = commits.head;
	while (current) {
		next = next->next;
		kfree(current);
		current = next;
	}
	commits.head = 0;
	return 0;
}

static int fs_append_to_commit_list(struct fs_commit_list_entry *entry) {
	struct fs_commit_list_entry *current = commits.head, *prev = 0;
	while (current && !(entry->data_type == current->data_type && entry->number == current->number)) {
		prev = current;
		current = current->next;
	}
	if (prev) {
		prev->next = entry;
		entry->prev = prev;
	}
	else {
		commits.head = entry;
	}
	if (current) {
		if (entry->op == FS_COMMIT_MODIFY && current->op == FS_COMMIT_CREATE)
			entry->op = FS_COMMIT_CREATE;
		entry->next = current->next;
		current->next->prev = entry;
		kfree(current);
	}
	return 0;
}

static int fs_stage_inode(struct fs_inode *node, enum fs_commit_op_type op) {
	struct fs_commit_list_entry *entry = kmalloc(sizeof(struct fs_commit_list_entry));
	memset(entry, 0, sizeof(struct fs_commit_list_entry));

	entry->data_type = FS_COMMIT_INODE;
	entry->number = node->inode_number;
	entry->op = op;
	entry->data.node = node;

	fs_append_to_commit_list(entry);

	return 0;
}

static int fs_stage_data_block(uint32_t index, unsigned char *buffer, enum fs_commit_op_type op) {
	struct fs_commit_list_entry *entry = kmalloc(sizeof(struct fs_commit_list_entry));
	memset(entry, 0, sizeof(struct fs_commit_list_entry));

	entry->data_type = FS_COMMIT_BLOCK;
	entry->number = index;
	entry->op = op;
	entry->data.to_write = kmalloc(sizeof(uint8_t) * FS_BLOCKSIZE);

	if (op == FS_COMMIT_MODIFY)
		memcpy(entry->data.to_write, buffer, FS_BLOCKSIZE);

	fs_append_to_commit_list(entry);

	return 0;
}

static int fs_do_delete_inode(struct fs_commit_list_entry *entry) {
	struct fs_inode *node = entry->data.node;
	uint32_t index = node->inode_number - 1;

	if (unset_bit(index, s.inode_bitmap_start, s.inode_start) < 0)
		return -1;

	entry->op = FS_COMMIT_CREATE;

	return 0;
}

static int fs_do_save_inode(struct fs_commit_list_entry *entry) {
	struct fs_inode *node = entry->data.node;
	struct fs_inode temp;
	uint8_t buffer[FS_BLOCKSIZE];
	uint32_t index = node->inode_number - 1;
	uint32_t inodes_per_block = FS_BLOCKSIZE / sizeof(struct fs_inode);
	uint32_t block = index / inodes_per_block;
	uint32_t offset = (index % inodes_per_block) * sizeof(struct fs_inode);

	if (entry->op == FS_COMMIT_CREATE) {
		if (set_bit(index, s.inode_bitmap_start, s.inode_start) < 0)
			return -1;
		entry->op = FS_COMMIT_DELETE;
		entry->is_completed = 1;
		printf("entry: %d\n", entry->is_completed);
	}

	if (entry->data.node) {
		ata_read(0, buffer, 1, s.inode_start + block);
//		memcpy(&temp, buffer + offset, sizeof(struct fs_inode));
		memcpy(buffer + offset, node, sizeof(struct fs_inode));
		ata_write(0, buffer, 1, s.inode_start + block);
//		memcpy(node, &temp, sizeof(struct fs_inode));
		entry->is_completed = 1;
	}

	return 0;
}

static int fs_do_delete_data(struct fs_commit_list_entry *entry) {
	uint32_t index = entry->number;

	if (unset_bit(index, s.block_bitmap_start, s.free_block_start) < 0) {
		return -1;
	}

	entry->op = FS_COMMIT_CREATE;
	entry->is_completed = 1;
	return 0;
}

static int fs_do_save_data(struct fs_commit_list_entry *entry) {
	uint32_t index = entry->number;
	uint8_t *temp;
	if (entry->op == FS_COMMIT_CREATE) {
		if (set_bit(index, s.block_bitmap_start, s.free_block_start) < 0) {
			return -1;
		}
		entry->op = FS_COMMIT_DELETE;
		entry->is_completed = 1;
	}

	temp = entry->data.to_write;
	//ata_read(0, entry->data.to_revert, 1, s.free_block_start + index);
	ata_write(0, temp, 1, s.free_block_start + index);
	entry->is_completed = 1;

	return 0;
}

static struct fs_inode *fs_create_new_inode(bool is_directory) {
	struct fs_inode *node;
	uint32_t inode_number;

	if (fs_get_available_inode(&inode_number) < 0) {
		return 0;
	}

	node = kmalloc(sizeof(struct fs_inode));
	memset(node, 0, sizeof(struct fs_inode));
	node->inode_number = inode_number;
	node->is_directory = is_directory;

	fs_stage_inode(node, FS_COMMIT_CREATE);

	return node;
}

static struct fs_inode *fs_get_inode(uint32_t inode_number) {

	uint8_t buffer[FS_BLOCKSIZE];
	struct fs_inode *node;
	uint32_t index = inode_number - 1;
	uint32_t inodes_per_block = FS_BLOCKSIZE / sizeof(struct fs_inode);
	uint32_t block = index / inodes_per_block;
	uint32_t offset = (index % inodes_per_block) * sizeof(struct fs_inode);
	bool is_active;

	if (check_bit(index, s.inode_bitmap_start, s.inode_start, &is_active) < 0) {
		return 0;
	}
	if (is_active == 0) {
		return 0;
	}

	node = kmalloc(sizeof(struct fs_inode));
	ata_read(0, buffer, 1, s.inode_start + block);
	memcpy(node, buffer + offset, sizeof(struct fs_inode));

	return node;
}

static int fs_save_inode(struct fs_inode *node) {
	uint32_t index = node->inode_number - 1;
	bool is_active;

	if (check_bit(index, s.inode_bitmap_start, s.inode_start, &is_active) < 0)
		return -1;
	if (is_active == 0)
		return -1;

	fs_stage_inode(node, FS_COMMIT_MODIFY);

	return 0;
}

static int fs_delete_inode(struct fs_inode *node) {
	uint32_t i;
	fs_stage_inode(node, FS_COMMIT_DELETE);
	for (i = 0; i < node->direct_addresses_len; i++) {
		fs_stage_data_block(node->direct_addresses[i], 0, FS_COMMIT_DELETE);
	}
	return 0;
}

static int fs_write_data_block(uint32_t index, uint8_t *buffer) {
	bool is_active;
	if (check_bit(index, s.block_bitmap_start, s.free_block_start, &is_active) < 0) {
		return -1;
	}
	if (is_active == 0) {
		return -1;
	}

	fs_stage_data_block(index, buffer, FS_COMMIT_MODIFY);
	return 0;
}

static int fs_delete_data_block(uint32_t index, uint8_t *buffer) {
	fs_stage_data_block(index, buffer, FS_COMMIT_DELETE);
	return 0;
}

static int fs_read_data_blocks(uint32_t index, uint8_t *buffer, uint32_t blocks) {
	bool is_active;
	if (check_bit(index, s.block_bitmap_start, s.free_block_start, &is_active) < 0) {
		return -1;
	}
	if (is_active == 0) {
		return -1;
	}
	ata_read(0, buffer, 1, s.free_block_start + index);
	return 0;
}

static struct fs_dir_record_list *fs_dir_alloc(uint32_t list_len) {
	struct fs_dir_record_list *ret = kmalloc(sizeof(struct fs_dir_record_list));
	ret->changed = hash_set_init(19);
	ret->list_len = list_len;
	ret->list = kmalloc(sizeof(struct fs_dir_record) * list_len);
	return ret;
}

static void fs_dir_dealloc(struct fs_dir_record_list *dir_list) {
	kfree(dir_list->list);
	hash_set_dealloc(dir_list->changed);
	kfree(dir_list);
}

static struct fs_dir_record_list *fs_readdir(struct fs_inode *node) {
	uint8_t buffer[FS_BLOCKSIZE * node->direct_addresses_len];
	uint32_t num_files = node->sz / sizeof(struct fs_dir_record);
	struct fs_dir_record_list *res = fs_dir_alloc(num_files);
	struct fs_dir_record *files = res->list;

	uint32_t i;
	for (i = 0; i < node->direct_addresses_len; i++) {
		fs_read_data_blocks(node->direct_addresses[i], buffer + i * FS_BLOCKSIZE, 1);
	}

	for (i = 0; i < num_files; i++) {
		memcpy(&files[i], buffer + sizeof(struct fs_dir_record) * i, sizeof(struct fs_dir_record));
	}

	return res;
}

static void fs_printdir_inorder(struct fs_dir_record_list *dir_list) {
	struct fs_dir_record *files = dir_list->list;
	while (1) {
		printf("%s\n", files->filename);
		if (files->offset_to_next == 0)
			return;
		files += files->offset_to_next;
	}
}

static int fs_inode_resize(struct fs_inode *node, uint32_t num_blocks){
	uint32_t i;
	if (num_blocks > FS_INODE_MAXBLOCKS)
		return -1;
	for (i = node->direct_addresses_len; i < num_blocks; i++){
		if (fs_get_available_block(&(node->direct_addresses[i])) < 0) {
			return -1;
		}
		fs_stage_data_block(node->direct_addresses[i], 0, FS_COMMIT_CREATE);
	}
	for (i = node->direct_addresses_len; i > num_blocks; i--) {
		fs_stage_data_block(node->direct_addresses[i-1], 0, FS_COMMIT_DELETE);
		node->direct_addresses[i-1] = 0;
	}
	node->direct_addresses_len = num_blocks;
	return 0;
}

static struct fs_dir_record *fs_lookup_dir_prev(char *filename, struct fs_dir_record_list *dir_list) {
	struct fs_dir_record *iter = dir_list->list, *prev = 0;
	while (strcmp(iter->filename, filename) < 0) {
		prev = iter;
		if (iter->offset_to_next == 0)
			break;
		iter += iter->offset_to_next;
	}
	return prev;
}

static struct fs_dir_record *fs_lookup_dir_exact(char *filename, struct fs_dir_record_list *dir_list) {
	struct fs_dir_record *iter = dir_list->list, *prev = 0;
	while (strcmp(iter->filename, filename) <= 0) {
		prev = iter;
		if (iter->offset_to_next == 0)
			break;
		iter += iter->offset_to_next;
	}
	return (strcmp(prev->filename, filename) == 0) ? prev : 0;
}

static struct fs_inode *fs_lookup_dir_node(char *filename, struct fs_dir_record_list *dir_list) {
	struct fs_dir_record *res = fs_lookup_dir_exact(filename, dir_list);
	return res ? fs_get_inode(res->inode_number) : 0;
}

static int fs_dir_record_insert_after(struct fs_dir_record_list *dir_list,
		struct fs_dir_record *prev,
		struct fs_dir_record *new) {

	struct fs_dir_record *list = dir_list->list;
	struct fs_dir_record *new_list = kmalloc((dir_list->list_len + 1) * sizeof(struct fs_dir_record));
	struct fs_dir_record *new_pos = new_list + dir_list->list_len, *new_prev = new_list + (prev - list);
	memcpy(new_list, list, dir_list->list_len * sizeof(struct fs_dir_record));

	if (prev) {
		memcpy(new_pos, new, sizeof(struct fs_dir_record));
		if (prev->offset_to_next != 0)
			new_pos->offset_to_next = new_prev + new_prev->offset_to_next - new_pos;
		else
			new_pos->offset_to_next = 0;

		new_prev->offset_to_next = new_pos - new_prev;
		hash_set_add(dir_list->changed, (new_prev - new_list) * sizeof(struct fs_dir_record) / FS_BLOCKSIZE);
		hash_set_add(dir_list->changed, ((new_prev - new_list + 1) * sizeof(struct fs_dir_record) - 1) / FS_BLOCKSIZE);
	}
	else {
		memcpy(new_pos, new_list, sizeof(struct fs_dir_record));
		new_pos->offset_to_next = new_pos - new_list;
		memcpy(new_list, new, sizeof(struct fs_dir_record));
		new_list->offset_to_next = new_list - new_pos;

		hash_set_add(dir_list->changed, 0);
		hash_set_add(dir_list->changed, (sizeof(struct fs_dir_record) - 1)/FS_BLOCKSIZE);
	}
	hash_set_add(dir_list->changed, (new_pos - new_list) * sizeof(struct fs_dir_record) / FS_BLOCKSIZE);
	hash_set_add(dir_list->changed, ((new_pos - new_list + 1) * sizeof(struct fs_dir_record) - 1) / FS_BLOCKSIZE);
	kfree (list);
	dir_list->list = new_list;
	dir_list->list_len++;
	return 0;
}

static int fs_dir_record_rm_after(struct fs_dir_record_list *dir_list,
		struct fs_dir_record *prev) {
	struct fs_dir_record *to_rm, *next, *last, *last_prev, *list_head;
	bool is_removing_end;

	list_head = dir_list->list;
	last = dir_list->list + dir_list->list_len - 1;
	to_rm = prev + prev->offset_to_next;
	next = to_rm + to_rm->offset_to_next;
	last_prev = fs_lookup_dir_prev(last->filename, dir_list);
	is_removing_end = to_rm->offset_to_next == 0;

	if (last != to_rm) {
		memcpy(to_rm, last, sizeof(struct fs_dir_record));

		if (last == next)
			next = to_rm;
		if (last == prev)
			prev = to_rm;

		if (to_rm != last_prev)
			last_prev->offset_to_next = last_prev->offset_to_next - (last - to_rm);
		if (to_rm->offset_to_next != 0)
			to_rm->offset_to_next = to_rm->offset_to_next + (last - to_rm);

		hash_set_add(dir_list->changed, (to_rm - list_head) * sizeof(struct fs_dir_record) / FS_BLOCKSIZE);
		hash_set_add(dir_list->changed, ((to_rm - list_head + 1) * sizeof(struct fs_dir_record) - 1) / FS_BLOCKSIZE);

		hash_set_add(dir_list->changed, (last_prev - list_head) * sizeof(struct fs_dir_record) / FS_BLOCKSIZE);
		hash_set_add(dir_list->changed, ((last_prev - list_head + 1) * sizeof(struct fs_dir_record) - 1) / FS_BLOCKSIZE);

	}

	if (is_removing_end)
		prev->offset_to_next = 0;
	else
		prev->offset_to_next = next - prev;

	memset(last, 0, sizeof(struct fs_dir_record));

	hash_set_add(dir_list->changed, (last - list_head) * sizeof(struct fs_dir_record) / FS_BLOCKSIZE);
	hash_set_add(dir_list->changed, ((last - list_head + 1) * sizeof(struct fs_dir_record) - 1) / FS_BLOCKSIZE);

	hash_set_add(dir_list->changed, (prev - list_head) * sizeof(struct fs_dir_record) / FS_BLOCKSIZE);
	hash_set_add(dir_list->changed, ((prev - list_head + 1) * sizeof(struct fs_dir_record) - 1) / FS_BLOCKSIZE);

	dir_list->list_len--;
	return 0;
}

static int fs_dir_add(struct fs_dir_record_list *current_files,
		struct fs_dir_record *new_file) {
	uint32_t len = current_files->list_len;
	struct fs_dir_record *lookup, *next;

	if (len < FS_EMPTY_DIR_SIZE) {
		return -1;
	}

	lookup = fs_lookup_dir_prev(new_file->filename, current_files);
	next = lookup + lookup->offset_to_next;
	if (strcmp(next->filename, new_file->filename) == 0) {
		return -1;
	}
	return fs_dir_record_insert_after(current_files, lookup, new_file);
}

static int fs_dir_rm(struct fs_dir_record_list *current_files, char *filename) {
	uint32_t len = current_files->list_len;
	struct fs_dir_record *lookup, *next;
	struct fs_inode *node;

	if (len < FS_EMPTY_DIR_SIZE) {
		return -1;
	}

	lookup = fs_lookup_dir_prev(filename, current_files);
	node = fs_lookup_dir_node(filename, current_files);
	next = lookup + lookup->offset_to_next;
	if (node && node->is_directory && node->sz == FS_EMPTY_DIR_SIZE_BYTES && next->is_directory && strcmp(next->filename, filename) == 0) {
		return fs_delete_inode(node) < 0 || fs_dir_record_rm_after(current_files, lookup) < 0 ? -1 : 0;
	}
	if (node)
		kfree(node);
	return -1;
}

static int fs_writedir(struct fs_inode *node, struct fs_dir_record_list *files){
	uint32_t new_len = files->list_len;
	uint8_t *buffer = kmalloc(sizeof(struct fs_dir_record) * new_len);
	uint32_t i, ending_index = (new_len * sizeof(struct fs_dir_record) - 1) / FS_BLOCKSIZE;
	uint32_t ending_num_indices = ceiling(((double) new_len * sizeof(struct fs_dir_record)) / FS_BLOCKSIZE);

	for (i = 0; i < new_len; i++) {
		memcpy(buffer + sizeof(struct fs_dir_record) * i, files->list + i, sizeof(struct fs_dir_record));
	}
	if (fs_inode_resize(node, ending_num_indices) < 0)
		return -1;
	for (i = 0; i <= ending_index; i++) {
		if (hash_set_lookup(files->changed, i)) {
			fs_write_data_block(node->direct_addresses[i], buffer + FS_BLOCKSIZE * i);
		}
	}
	node->sz = new_len * sizeof(struct fs_dir_record);
	kfree(buffer);
	return 0;
}

static struct fs_dir_record_list *fs_create_empty_dir(struct fs_inode *node) {
	struct fs_dir_record_list *list = fs_dir_alloc(FS_EMPTY_DIR_SIZE);
	struct fs_dir_record *links = list->list;
	strcpy(links[0].filename, ".");
	links[0].offset_to_next = 1;
	links[0].inode_number = node->inode_number;
	links[0].is_directory = 1;
	strcpy(links[1].filename, "..");
	links[1].inode_number = cwd;
	links[1].offset_to_next = 0;
	links[1].is_directory = 1;

	hash_set_add(list->changed, 0);
	hash_set_add(list->changed, (sizeof(struct fs_dir_record) * FS_EMPTY_DIR_SIZE - 1) / FS_BLOCKSIZE);

	return list;
}

static struct fs_dir_record *fs_init_record_by_filename(char *filename, struct fs_inode *new_node) {
	uint32_t filename_len = strlen(filename);
	struct fs_dir_record *link;
	if (filename_len > FS_FILENAME_MAXLEN) {
		return 0;
	}

	link = kmalloc(sizeof(struct fs_dir_record));
	strcpy(link->filename,filename);
	link->inode_number = new_node->inode_number;
	link->is_directory = new_node->is_directory;
	return link;
}

static struct fs_inode *fs_create_file(char *filename, struct fs_dir_record_list *dir_list, struct fs_inode *dir_node) {
	struct fs_inode *new_node;
	struct fs_dir_record *new_record;
	bool is_directory = 0;
	int ret;

	new_node = fs_create_new_inode(is_directory);
	new_record = fs_init_record_by_filename(filename, new_node);

	fs_dir_add(dir_list, new_record);
	ret = fs_writedir(dir_node, dir_list);
	fs_save_inode(dir_node);

	return ret==0 ? new_node : 0;
}

static int fs_write_file_range(struct fs_inode *node, uint8_t *buffer, uint32_t start, uint32_t n) {
	uint32_t direct_addresses_start = start / FS_BLOCKSIZE, direct_addresses_end = (start + n - 1) / FS_BLOCKSIZE;
	uint32_t start_offset = start % FS_BLOCKSIZE, end_offset = (start + n - 1) % FS_BLOCKSIZE;
	uint32_t i, total_copy_length = 0;

	if (fs_inode_resize(node,  direct_addresses_end + 1) < 0) {
		return -1;
	}

	for (i = direct_addresses_start; i <= direct_addresses_end; i++) {
		uint8_t buffer_part[FS_BLOCKSIZE];
		uint8_t *copy_start = buffer_part;
		uint32_t buffer_part_len = FS_BLOCKSIZE;
		memset(buffer_part, 0, sizeof(buffer_part));
		if (i == direct_addresses_start) {
			copy_start += start_offset;
		}
		if (i == direct_addresses_end) {
			buffer_part_len -= FS_BLOCKSIZE - end_offset;
		}
		memcpy(copy_start, buffer + total_copy_length, buffer_part_len);
		fs_write_data_block(node->direct_addresses[i], buffer_part);
		total_copy_length += buffer_part_len;
	}
	if (start + n > node->sz)
		node->sz = start + n;
	fs_save_inode(node);

	return total_copy_length;
}

static int fs_read_file_range(struct fs_inode *node, uint8_t *buffer, uint32_t start, uint32_t n) {
	uint32_t direct_addresses_start = start / FS_BLOCKSIZE, direct_addresses_end = (start + n - 1) / FS_BLOCKSIZE;
	uint32_t start_offset = start % FS_BLOCKSIZE, end_offset = (start + n) % FS_BLOCKSIZE;
	uint32_t i, total_copy_length = 0;

	for (i = direct_addresses_start; i <= direct_addresses_end; i++) {
		uint8_t buffer_part[FS_BLOCKSIZE];
		uint8_t *copy_start = buffer_part;
		uint32_t buffer_part_len = FS_BLOCKSIZE;
		memset(buffer_part, 0, sizeof(buffer_part));
		if (i == direct_addresses_start) {
			copy_start += start_offset;
		}
		if (i == direct_addresses_end) {
			buffer_part_len -= FS_BLOCKSIZE - end_offset - 1;
		}
		fs_read_data_blocks(node->direct_addresses[i], buffer_part, 1);
		memcpy(buffer + total_copy_length, copy_start, buffer_part_len);
		total_copy_length += buffer_part_len;
	}

	return total_copy_length;
}

static int fs_try_commit(struct fs_commit_list_entry *position) {
	while (position) {
		int ret = 0;
		if (position->data_type == FS_COMMIT_INODE) {
			switch (position->op) {
				case FS_COMMIT_CREATE:
				case FS_COMMIT_MODIFY:
					ret = fs_do_save_inode(position);
					break;
				case FS_COMMIT_DELETE:
					ret = fs_do_delete_inode(position);
					break;
			}
		}
		if (position->data_type == FS_COMMIT_BLOCK) {
			switch (position->op) {
				case FS_COMMIT_CREATE:
				case FS_COMMIT_MODIFY:
					ret = fs_do_save_data(position);
					break;
				case FS_COMMIT_DELETE:
					ret = fs_do_delete_data(position);
					break;
			}
		}
		if (ret < 0) {
			printf("commit failed\n");
			return ret;
		}
		position = position->next;
	}
	return 0;
}

static int fs_commit() {
	struct fs_commit_list_entry *start = commits.head;
	int ret = fs_try_commit(start);
	return ret;
}

int fs_lsdir() {
	struct fs_inode *node = fs_get_inode(cwd);
	struct fs_dir_record_list *list = fs_readdir(node);
	fs_printdir_inorder(list);
	fs_dir_dealloc(list);
	kfree(node);
	return 0;
}

int fs_mkdir(char *filename) {
	struct fs_dir_record_list *new_dir_record_list, *cwd_record_list;
	struct fs_dir_record *new_cwd_record;
	struct fs_inode *new_node, *cwd_node;
	bool is_directory = 1;
	int ret;

	fs_init_commit_list();

	new_node = fs_create_new_inode(is_directory);
	cwd_node = fs_get_inode(cwd);
	cwd_record_list = fs_readdir(cwd_node);
	new_dir_record_list = fs_create_empty_dir(new_node);
	new_cwd_record = fs_init_record_by_filename(filename, new_node);

	fs_writedir(new_node, new_dir_record_list);

	fs_dir_add(cwd_record_list, new_cwd_record);
	ret = fs_writedir(cwd_node, cwd_record_list);

	fs_save_inode(new_node);
	fs_save_inode(cwd_node);

	if (ret == 0)
		ret = fs_commit();

	fs_dir_dealloc(new_dir_record_list);
	fs_dir_dealloc(cwd_record_list);
	kfree(new_cwd_record);
	kfree(new_node);
	kfree(cwd_node);
	return ret;
}

int fs_rmdir(char *filename) {
	struct fs_dir_record_list *cwd_record_list;
	struct fs_inode *cwd_node;
	int ret;

	fs_init_commit_list();

	cwd_node = fs_get_inode(cwd);
	cwd_record_list = fs_readdir(cwd_node);

	ret = fs_dir_rm(cwd_record_list, filename);
	fs_writedir(cwd_node, cwd_record_list);
	fs_save_inode(cwd_node);

	if (ret == 0)
		ret = fs_commit();

	fs_dir_dealloc(cwd_record_list);
	kfree(cwd_node);

	return ret;
}

int fs_open(char *filename, uint8_t mode) {
	struct fs_dir_record_list *cwd_record_list;
	struct fs_inode *cwd_node, *node_to_access;
	int ret = -1;

	fs_init_commit_list();
	cwd_node = fs_get_inode(cwd);
	cwd_record_list = fs_readdir(cwd_node);
	node_to_access = fs_lookup_dir_node(filename, cwd_record_list);

	if (!node_to_access && (mode & FILE_MODE_WRITE)) {
		node_to_access = fs_create_file(filename, cwd_record_list, cwd_node);
	}

	if (node_to_access)
		ret = fdtable_add(&table, node_to_access, mode);

	fs_commit();

	return ret;
}

int fs_close(int fd) {
	int ret;
	ret = fdtable_rm(&table, fd);
	return ret;
}

int fs_write(int fd, uint8_t *buffer, uint32_t n) {
	struct fdtable_entry *entry = fdtable_get(&table, fd);
	uint32_t original_offset = entry->offset, new_offset;
	fs_init_commit_list();
	if (!entry || !(FILE_MODE_WRITE & entry->mode))
		return -1;
	fdtable_entry_seek_offset(entry, n, 0);
	new_offset = entry->offset;
	fs_write_file_range(entry->inode, buffer, original_offset, new_offset - original_offset);

	fs_commit();
	return new_offset - original_offset;
}

int fs_read(int fd, uint8_t *buffer, uint32_t n) {
	struct fdtable_entry *entry = fdtable_get(&table, fd);
	uint32_t original_offset = entry->offset, new_offset;
	if (!entry || !(FILE_MODE_READ & entry->mode))
		return -1;
	fdtable_entry_seek_offset(entry, n, 1);
	new_offset = entry->offset;
	fs_read_file_range(entry->inode, buffer, original_offset, new_offset - original_offset);
	return new_offset - original_offset;
}

int fs_chdir(char *filename) {
	struct fs_inode *cwd_node = fs_get_inode(cwd), *new_node;
	struct fs_dir_record_list *cwd_record_list = fs_readdir(cwd_node);
	uint8_t ret;
	new_node = fs_lookup_dir_node(filename, cwd_record_list);

	ret = new_node && new_node->is_directory;
	cwd = new_node->inode_number;

	kfree(new_node);
	kfree(cwd_node);
	fs_dir_dealloc(cwd_record_list);
	return ret ? -1 : 0;
}

int fs_unlink(char *filename) {
	struct fs_inode *cwd_node = fs_get_inode(cwd), *node_to_rm;
	struct fs_dir_record_list *cwd_record_list = fs_readdir(cwd_node);
	struct fs_dir_record *prev;
	uint8_t ret = 0;
	node_to_rm = fs_lookup_dir_node(filename, cwd_record_list);
	prev = fs_lookup_dir_prev(filename, cwd_record_list);
	fs_dir_record_rm_after(cwd_record_list, prev);

	fs_init_commit_list();
	fs_writedir(cwd_node, cwd_record_list);
	fs_delete_inode(node_to_rm);
	fs_commit();

	kfree(node_to_rm);
	kfree(cwd_node);
	fs_dir_dealloc(cwd_record_list);
	return ret;
}

int fs_init(void) {
	int ret = 0, formatted;
	reserved_bits = hash_set_init(FS_RESERVED_BITS_COUNT);
	formatted = fs_check_format();
	memset(&table, 0, sizeof(struct fdtable));
	if (!formatted) {
		ret = fs_mkfs();
	}
	cwd = 1;
	return ret;
}

int fs_stat(char *filename, struct fs_stat *stat) {
	struct fs_inode *cwd_node = fs_get_inode(cwd), *node;
	struct fs_dir_record_list *cwd_record_list = fs_readdir(cwd_node);
	node = fs_lookup_dir_node(filename, cwd_record_list);
	if (node) {
		stat->inode_number = node->inode_number;
		stat->is_directory = node->is_directory;
		stat->size = node->sz;
		stat->links = 1;
		stat->num_blocks = node->direct_addresses_len;
		return 0;
	}
	return -1;
}

int fs_mkfs(void) {

	uint8_t wbuffer[FS_BLOCKSIZE];

	uint32_t superblock_num_blocks = ceiling((double) sizeof(struct fs_superblock) / FS_BLOCKSIZE);
	uint32_t available_blocks = FS_SIZE - superblock_num_blocks;
	uint32_t free_blocks = (uint32_t) ((double) (available_blocks)/(1.0 + (double) (sizeof(struct fs_inode) + .125)/(4.0 * FS_BLOCKSIZE) + .125/(FS_BLOCKSIZE)));
	uint32_t total_inodes = free_blocks / 8;
	uint32_t total_bits = free_blocks;
	uint32_t inode_sector_size = ceiling((double)(total_inodes * sizeof(struct fs_inode))/FS_BLOCKSIZE);
	uint32_t inode_bit_sector_size = ceiling((double)total_bits/FS_BLOCKSIZE);
	uint32_t bit_sector_size = ceiling((double)total_bits/FS_BLOCKSIZE);

	struct fs_superblock s_new;

	s_new.magic = FS_MAGIC;
	s_new.blocksize = FS_BLOCKSIZE;
	s_new.inode_bitmap_start = superblock_num_blocks;
	s_new.inode_start = s_new.inode_bitmap_start + inode_bit_sector_size;
	s_new.block_bitmap_start = s_new.inode_start + inode_sector_size;
	s_new.free_block_start = s_new.block_bitmap_start + bit_sector_size;
	s_new.num_inodes = total_inodes;
	s_new.num_free_blocks = free_blocks;

	memcpy(wbuffer, &s_new, sizeof(s_new));
	ata_write(0, wbuffer, 1, 0);
	memcpy(&s, &s_new, sizeof(s));

	fs_init_commit_list();

	struct fs_inode *new_node = fs_create_new_inode(1);
	struct fs_dir_record_list *new_records = fs_create_empty_dir(new_node);

	fs_writedir(new_node, new_records);
	fs_save_inode(new_node);

	fs_commit();

	kfree(new_node);
	fs_dir_dealloc(new_records);

	return 0;
}
