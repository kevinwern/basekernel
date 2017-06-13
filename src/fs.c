/*
Copyright (C) 2017 The University of Notre Dame
This software is distributed under the GNU General Public License.
See the file LICENSE for details.
*/

#include "kerneltypes.h"
#include "ata.h"
#include "kmalloc.h"
#include "fs.h"
#include "fs_ata.h"
#include "fs_transaction.h"
#include "fdtable.h"
#include "string.h"
#include "hashtable.h"

static uint32_t ceiling(double d)
{
    uint32_t i = (uint32_t) d;
    if (d == (double) i)
	    return i;
    return i + 1;
}

static uint32_t ata_blocksize;

static struct fs_superblock *super;
static struct fdtable table;
static uint32_t cwd;
static struct fs_transaction transaction;

static void fs_print_superblock(struct fs_superblock *s)
{
	printf("fs: magic: %u, blocksize: %u, free_blocks: %u, inode_count: %u, inode_bitmap_start: %u, inode_start: %u, block_bitmap_start: %u, free_block_start: %u \n",
			super->magic,
			super->blocksize,
			super->num_free_blocks,
			super->num_inodes,
			super->inode_bitmap_start,
			super->inode_start,
			super->block_bitmap_start,
			super->free_block_start);
}

static void fs_print_inode(struct fs_inode *n)
{
	uint32_t i;
	printf("fs: inode_number: %u, is_directory: %u, sz: %u, direct_addresses_len: %u, link_count:%u\n",
			n->inode_number,
			n->is_directory,
			n->sz,
			n->direct_addresses_len,
			n->link_count);
	for (i = 0; i < n->direct_addresses_len; i++)
		printf("fs: direct_addresses[%u]: %u\n", i, n->direct_addresses[i]);
}

static void fs_print_dir_record(struct fs_dir_record *d)
{
	printf("fs: filename: %s, inode_number: %u, offset: %d\n",
			d->filename,
			d->inode_number,
			d->offset_to_next);
}

static void fs_print_dir_record_list(struct fs_dir_record_list *l)
{
	uint32_t i;
	for (i = 0; i < l->list_len; i++) {
		fs_print_dir_record(l->list + i);
	}
}

static void fs_print_transaction_entry(struct fs_transaction_entry *entry)
{
	char *opstring, *datastring;
	switch (entry->data_type) {
		case FS_TRANSACTION_INODE:
			datastring = "inode";
			break;
		case FS_TRANSACTION_BLOCK:
			datastring= "data block";
			break;
	}
	switch (entry->op) {
		case FS_TRANSACTION_CREATE:
			opstring = "create";
			break;
		case FS_TRANSACTION_MODIFY:
			opstring = "modify";
			break;
		case FS_TRANSACTION_DELETE:
			opstring = "delete";
			break;
	}
	printf("fs: op: %s, data: %s, number: %u\n", opstring, datastring, entry->number);
	if (entry->data_type == FS_TRANSACTION_INODE){
		fs_print_inode(&entry->data.node);
	}
}

static void fs_print_transaction(struct fs_transaction *t)
{
	struct fs_transaction_entry *start = t->head;
	printf("fs: transaction:\n");
	while (start) {
		fs_print_transaction_entry(start);
		start = start->next;
	}
}

static int fs_get_available_block(uint32_t *res)
{
	return fs_ata_ffs_range(super->block_bitmap_start, super->free_block_start, res);
}

static int fs_get_available_inode(uint32_t *res)
{
	int ret = fs_ata_ffs_range(super->inode_bitmap_start, super->inode_start, res);
	*res += 1;
	return ret;
}

static struct fs_inode *fs_create_new_inode(bool is_directory)
{
	struct fs_inode *node;
	uint32_t inode_number;

	if (fs_get_available_inode(&inode_number) < 0)
		return 0;

	node = kmalloc(sizeof(struct fs_inode));
	if (!node)
		return 0;

	memset(node, 0, sizeof(struct fs_inode));
	node->inode_number = inode_number;
	node->is_directory = is_directory;
	node->link_count = is_directory ? 1 : 0;

	if (fs_transaction_stage_inode(&transaction, node, FS_TRANSACTION_CREATE) < 0) {
		kfree(node);
		return 0;
	}

	return node;
}

static struct fs_inode *fs_get_inode(uint32_t inode_number)
{

	uint8_t buffer[FS_BLOCKSIZE];
	struct fs_inode *node;
	uint32_t index = inode_number - 1;
	uint32_t inodes_per_block = FS_BLOCKSIZE / sizeof(struct fs_inode);
	uint32_t block = index / inodes_per_block;
	uint32_t offset = (index % inodes_per_block) * sizeof(struct fs_inode);
	bool is_active;

	if (fs_ata_check_bit(index, super->inode_bitmap_start, super->inode_start, &is_active) < 0)
		return 0;
	if (is_active == 0)
		return 0;

	node = kmalloc(sizeof(struct fs_inode));
	if (node) {
		if (fs_ata_read_block(super->inode_start + block, buffer) < 0) {
			kfree(node);
			node = 0;
		}
		else {
			memcpy(node, buffer + offset, sizeof(struct fs_inode));
		}
	}

	return node;
}

static int fs_save_inode(struct fs_inode *node)
{
       uint32_t index = node->inode_number - 1;
       bool is_active;

       if (fs_ata_check_bit(index, super->inode_bitmap_start, super->inode_start, &is_active) < 0)
	       return -1;
       if (is_active == 0)
	       return -1;

       fs_transaction_stage_inode(&transaction, node, FS_TRANSACTION_MODIFY);

       return 0;
}

static int fs_delete_data_block(uint32_t index, uint8_t *buffer)
{
	return fs_transaction_stage_data(&transaction, index, buffer, FS_TRANSACTION_DELETE);
}

static int fs_delete_inode_or_decrement_links(struct fs_inode *node)
{
       uint32_t i;
       if (node->is_directory)
	       node->link_count--;
       node->link_count--;
       if (node->link_count > 0)
	       return fs_transaction_stage_inode(&transaction, node, FS_TRANSACTION_MODIFY);
       if (fs_transaction_stage_inode(&transaction, node, FS_TRANSACTION_DELETE) < 0)
	       return -1;
       for (i = 0; i < node->direct_addresses_len; i++) {
	       if (fs_delete_data_block(node->direct_addresses[i], 0) < 0)
		       return -1;
       }
       return 0;
}

static int fs_write_data_block(uint32_t index, uint8_t *buffer)
{
	bool is_active;
	if (fs_ata_check_bit(index, super->block_bitmap_start, super->free_block_start, &is_active) < 0) {
		return -1;
	}
	if (is_active == 0) {
		return -1;
	}

	fs_transaction_stage_data(&transaction, index, buffer, FS_TRANSACTION_MODIFY);
	return 0;
}

static int fs_read_data_blocks(uint32_t index, uint8_t *buffer, uint32_t blocks)
{
	bool is_active;
	if (fs_ata_check_bit(index, super->block_bitmap_start, super->free_block_start, &is_active) < 0) {
		return -1;
	}
	if (is_active == 0) {
		return -1;
	}
	fs_ata_read_block(super->free_block_start + index, buffer);
	return 0;
}

static struct fs_dir_record_list *fs_dir_alloc(uint32_t list_len)
{
	struct fs_dir_record_list *ret = kmalloc(sizeof(struct fs_dir_record_list));
	if (ret)
		ret->changed = hash_set_init(19);
		ret->list_len = list_len;
		ret->list = kmalloc(sizeof(struct fs_dir_record) * list_len);
		if (!ret->list || !ret->changed) {
			if (ret->changed)
				hash_set_dealloc(ret->changed);
			if (ret->list)
				kfree(ret->list);
			kfree(ret);
			ret = 0;
		}
	return ret;
}

static void fs_dir_dealloc(struct fs_dir_record_list *dir_list)
{
	kfree(dir_list->list);
	hash_set_dealloc(dir_list->changed);
	kfree(dir_list);
}

static struct fs_dir_record_list *fs_readdir(struct fs_inode *node)
{
	uint8_t buffer[FS_BLOCKSIZE * node->direct_addresses_len];
	uint32_t num_files = node->sz / sizeof(struct fs_dir_record);
	struct fs_dir_record_list *res = fs_dir_alloc(num_files);
	struct fs_dir_record *files = res->list;

	if (!res)
		return 0;

	uint32_t i;
	for (i = 0; i < node->direct_addresses_len; i++) {
		if (fs_read_data_blocks(node->direct_addresses[i], buffer + i * FS_BLOCKSIZE, 1) < 0) {
			fs_dir_dealloc(res);
			return 0;
		}
	}

	for (i = 0; i < num_files; i++) {
		memcpy(&files[i], buffer + sizeof(struct fs_dir_record) * i, sizeof(struct fs_dir_record));
	}

	return res;
}

static void fs_printdir_inorder(struct fs_dir_record_list *dir_list)
{
	struct fs_dir_record *files = dir_list->list;
	while (1) {
		printf("%s\n", files->filename);
		if (files->offset_to_next == 0)
			return;
		files += files->offset_to_next;
	}
}

static int fs_inode_resize(struct fs_inode *node, uint32_t num_blocks)
{
	uint32_t i;
	if (num_blocks > FS_INODE_MAXBLOCKS)
		return -1;
	for (i = node->direct_addresses_len; i < num_blocks; i++){
		if (fs_get_available_block(&(node->direct_addresses[i])) < 0) {
			return -1;
		}
		fs_transaction_stage_data(&transaction, node->direct_addresses[i], 0, FS_TRANSACTION_CREATE);
	}
	for (i = node->direct_addresses_len; i > num_blocks; i--) {
		fs_transaction_stage_data(&transaction, node->direct_addresses[i-1], 0, FS_TRANSACTION_DELETE);
		node->direct_addresses[i-1] = 0;
	}
	node->direct_addresses_len = num_blocks;
	return 0;
}

static struct fs_dir_record *fs_lookup_dir_prev(char *filename, struct fs_dir_record_list *dir_list)
{
	struct fs_dir_record *iter = dir_list->list, *prev = 0;
	while (strcmp(iter->filename, filename) < 0) {
		prev = iter;
		if (iter->offset_to_next == 0)
			break;
		iter += iter->offset_to_next;
	}
	return prev;
}

static struct fs_dir_record *fs_lookup_dir_exact(char *filename, struct fs_dir_record_list *dir_list)
{
	struct fs_dir_record *iter = dir_list->list, *prev = 0;
	while (strcmp(iter->filename, filename) <= 0) {
		prev = iter;
		if (iter->offset_to_next == 0)
			break;
		iter += iter->offset_to_next;
	}
	return (strcmp(prev->filename, filename) == 0) ? prev : 0;
}

static struct fs_inode *fs_lookup_dir_node(char *filename, struct fs_dir_record_list *dir_list)
{
	struct fs_dir_record *res = fs_lookup_dir_exact(filename, dir_list);
	return res ? fs_get_inode(res->inode_number) : 0;
}

static int fs_dir_record_insert_after(struct fs_dir_record_list *dir_list,
		struct fs_dir_record *prev,
		struct fs_dir_record *new)
{
	struct fs_dir_record *list = dir_list->list;
	struct fs_dir_record *new_list;
	struct fs_dir_record *new_pos, *new_prev;

	new_list = kmalloc((dir_list->list_len + 1) * sizeof(struct fs_dir_record));
	memcpy(new_list, list, dir_list->list_len * sizeof(struct fs_dir_record));
	new_pos = new_list + dir_list->list_len;
	new_prev = new_list + (prev - list);

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
		struct fs_dir_record *prev)
{
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
		struct fs_dir_record *new_file,
		struct fs_inode *parent)
{
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
	if (fs_dir_record_insert_after(current_files, lookup, new_file) < 0)
		return -1;

	parent->link_count++;
	return 0;
}

static int fs_dir_rm(struct fs_dir_record_list *current_files,
		char *filename,
		struct fs_inode *parent)
{
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
		parent->link_count--;
		return fs_delete_inode_or_decrement_links(node) < 0 || fs_dir_record_rm_after(current_files, lookup) < 0 ? -1 : 0;
	}
	if (node)
		kfree(node);
	return -1;
}

static int fs_writedir(struct fs_inode *node, struct fs_dir_record_list *files)
{

	uint32_t new_len = files->list_len;
	uint8_t *buffer = kmalloc(sizeof(struct fs_dir_record) * new_len);
	uint32_t i, ending_index = (new_len * sizeof(struct fs_dir_record) - 1) / FS_BLOCKSIZE;
	uint32_t ending_num_indices = ceiling(((double) new_len * sizeof(struct fs_dir_record)) / FS_BLOCKSIZE);
	int ret = 0;

	for (i = 0; i < new_len; i++) {
		memcpy(buffer + sizeof(struct fs_dir_record) * i, files->list + i, sizeof(struct fs_dir_record));
	}
	if (fs_inode_resize(node, ending_num_indices) < 0) {
		ret = -1;
		goto cleanup;
	}
	for (i = 0; i <= ending_index; i++) {
		if (hash_set_lookup(files->changed, i)) {
			ret = fs_write_data_block(node->direct_addresses[i], buffer + FS_BLOCKSIZE * i);
			if (ret < 0)
				goto cleanup;
		}
	}
	node->sz = new_len * sizeof(struct fs_dir_record);
cleanup:
	kfree(buffer);
	return ret;
}

static struct fs_dir_record_list *fs_create_empty_dir(struct fs_inode *node)
{
	struct fs_dir_record_list *dir;
	struct fs_dir_record *records;

	if (!node)
		return 0;

	dir = fs_dir_alloc(FS_EMPTY_DIR_SIZE);
	if (!dir)
		return 0;

	records = dir->list;
	strcpy(records[0].filename, ".");
	records[0].offset_to_next = 1;
	records[0].inode_number = node->inode_number;
	records[0].is_directory = 1;
	strcpy(records[1].filename, "..");
	records[1].inode_number = cwd;
	records[1].offset_to_next = 0;
	records[1].is_directory = 1;

	hash_set_add(dir->changed, 0);
	hash_set_add(dir->changed, (sizeof(struct fs_dir_record) * FS_EMPTY_DIR_SIZE - 1) / FS_BLOCKSIZE);

	return dir;
}

static struct fs_dir_record *fs_init_record_by_filename(char *filename, struct fs_inode *new_node)
{
	uint32_t filename_len = strlen(filename);
	struct fs_dir_record *link;
	if (filename_len > FS_FILENAME_MAXLEN || !new_node) {
		return 0;
	}

	link = kmalloc(sizeof(struct fs_dir_record));
	if (!link)
		return 0;

	strcpy(link->filename,filename);
	link->inode_number = new_node->inode_number;
	link->is_directory = new_node->is_directory;
	new_node->link_count++;
	return link;
}

static struct fs_inode *fs_create_file(char *filename, struct fs_dir_record_list *dir_list, struct fs_inode *dir_node)
{
	struct fs_inode *new_node;
	struct fs_dir_record *new_record, *prev, *maybe_same_name;
	bool is_directory = 0;
	int ret = 0;

	new_node = fs_create_new_inode(is_directory);
	new_record = fs_init_record_by_filename(filename, new_node);
	prev = fs_lookup_dir_prev(filename, dir_list);
	maybe_same_name = prev + prev->offset_to_next;

	if (!new_node || !new_record || !strcmp(maybe_same_name->filename, filename))
		ret = -1;
	else
		ret = !fs_dir_record_insert_after(dir_list, prev, new_record) &&
			!fs_writedir(dir_node, dir_list) &&
			!fs_save_inode(dir_node) ? 0 : -1;

	if (new_record)
		kfree(new_record);
	if (ret < 0 && new_node) {
		kfree(new_node);
		new_node = 0;
	}

	return new_node;
}

static int fs_write_file_range(struct fs_inode *node, uint8_t *buffer, uint32_t start, uint32_t n)
{
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

static int fs_read_file_range(struct fs_inode *node, uint8_t *buffer, uint32_t start, uint32_t n)
{
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

int fs_lsdir()
{
	struct fs_inode *node = fs_get_inode(cwd);
	struct fs_dir_record_list *list = fs_readdir(node);
	int ret = node && list ? 0 : -1;

	if (list) {
		fs_printdir_inorder(list);
		fs_dir_dealloc(list);
	}
	if (node)
		kfree(node);
	return ret;
}

int fs_mkdir(char *filename)
{
	struct fs_dir_record_list *new_dir_record_list, *cwd_record_list;
	struct fs_dir_record *new_cwd_record;
	struct fs_inode *new_node, *cwd_node;
	bool is_directory = 1;
	int ret;

	fs_transaction_init(&transaction);

	new_node = fs_create_new_inode(is_directory);
	cwd_node = fs_get_inode(cwd);
	cwd_record_list = fs_readdir(cwd_node);
	new_dir_record_list = fs_create_empty_dir(new_node);
	new_cwd_record = fs_init_record_by_filename(filename, new_node);

	if (!new_node || !cwd_node || !cwd_record_list ||
			!new_dir_record_list || !new_cwd_record) {
		ret = -1;
		goto cleanup;
	}

	if (fs_writedir(new_node, new_dir_record_list) < 0 ||
		fs_dir_add(cwd_record_list, new_cwd_record, cwd_node) < 0 ||
		fs_writedir(cwd_node, cwd_record_list) < 0 ||
		fs_save_inode(new_node) < 0 ||
		fs_save_inode(cwd_node) < 0) {
		ret = -1;
		goto cleanup;
	}

	ret = fs_transaction_commit(&transaction);

cleanup:
	if (new_dir_record_list)
		fs_dir_dealloc(new_dir_record_list);
	if (cwd_record_list)
		fs_dir_dealloc(cwd_record_list);
	if (new_cwd_record)
		kfree(new_cwd_record);
	if (new_node)
		kfree(new_node);
	if (cwd_node)
		kfree(cwd_node);
	return ret;
}

int fs_rmdir(char *filename)
{
	struct fs_dir_record_list *cwd_record_list;
	struct fs_inode *cwd_node;
	int ret = -1;

	fs_transaction_init(&transaction);

	cwd_node = fs_get_inode(cwd);
	cwd_record_list = fs_readdir(cwd_node);

	if (cwd_node && cwd_record_list) {
		ret = !fs_dir_rm(cwd_record_list, filename, cwd_node) &&
			!fs_writedir(cwd_node, cwd_record_list) &&
			!fs_save_inode(cwd_node) &&
			!fs_transaction_commit(&transaction) ? 0 : -1;
	}

	if (cwd_record_list)
		fs_dir_dealloc(cwd_record_list);
	if (cwd_node)
		kfree(cwd_node);

	return ret;
}

int fs_open(char *filename, uint8_t mode)
{
	struct fs_dir_record_list *cwd_record_list;
	struct fs_inode *cwd_node, *node_to_access;
	int ret = -1;

	fs_transaction_init(&transaction);

	cwd_node = fs_get_inode(cwd);
	cwd_record_list = fs_readdir(cwd_node);
	node_to_access = fs_lookup_dir_node(filename, cwd_record_list);

	if (!cwd_node || !cwd_record_list) {
		goto cleanup;
	}

	if (!node_to_access && (mode & FILE_MODE_WRITE)) {
		node_to_access = fs_create_file(filename, cwd_record_list, cwd_node);
	}

	if (node_to_access)
		ret = !fdtable_add(&table, node_to_access, mode) && !fs_transaction_commit(&transaction) ? 0 : -1;

cleanup:
	if (cwd_node)
		kfree(cwd_node);
	if (cwd_record_list)
		fs_dir_dealloc(cwd_record_list);
	return ret;
}

int fs_close(int fd)
{
	return fdtable_rm(&table, fd);
}

int fs_write(int fd, uint8_t *buffer, uint32_t n)
{
	struct fdtable_entry *entry = fdtable_get(&table, fd);
	uint32_t original_offset = entry->offset, new_offset;

	fs_transaction_init(&transaction);
	if (!entry || !(FILE_MODE_WRITE & entry->mode))
		return -1;
	fdtable_entry_seek_offset(entry, n, 0);
	new_offset = entry->offset;
	if (fs_write_file_range(entry->inode, buffer, original_offset, new_offset - original_offset) < 0 ||
			fs_transaction_commit(&transaction) < 0)
		return -1;

	return new_offset - original_offset;
}

int fs_read(int fd, uint8_t *buffer, uint32_t n)
{
	struct fdtable_entry *entry = fdtable_get(&table, fd);
	uint32_t original_offset = entry->offset, new_offset;
	if (!entry || !(FILE_MODE_READ & entry->mode))
		return -1;
	fdtable_entry_seek_offset(entry, n, 1);
	new_offset = entry->offset;
	if (fs_read_file_range(entry->inode, buffer, original_offset, new_offset - original_offset) < 0)
		return -1;
	return new_offset - original_offset;
}

int fs_chdir(char *filename)
{
	struct fs_inode *cwd_node = fs_get_inode(cwd), *new_node = 0;
	struct fs_dir_record_list *cwd_record_list = fs_readdir(cwd_node);
	bool res = 0;

	if (!cwd_node || !cwd_record_list)
		goto cleanup;
	new_node = fs_lookup_dir_node(filename, cwd_record_list);

	res = new_node && new_node->is_directory;
	if (res)
		cwd = new_node->inode_number;

cleanup:
	if (new_node)
		kfree(new_node);
	if (cwd_node)
		kfree(cwd_node);
	if (cwd_record_list)
		fs_dir_dealloc(cwd_record_list);
	return res ? 0 : -1;
}

int fs_unlink(char *filename)
{
	struct fs_inode *cwd_node = fs_get_inode(cwd), *node_to_rm = 0;
	struct fs_dir_record_list *cwd_record_list = fs_readdir(cwd_node);
	struct fs_dir_record *prev;
	uint8_t ret = -1;

	fs_transaction_init(&transaction);

	if (!cwd_node || !cwd_record_list)
		goto cleanup;

	node_to_rm = fs_lookup_dir_node(filename, cwd_record_list);
	prev = fs_lookup_dir_prev(filename, cwd_record_list);

	if (node_to_rm) {
		ret = !fs_dir_record_rm_after(cwd_record_list, prev) &&
		!fs_writedir(cwd_node, cwd_record_list) &&
		!fs_delete_inode_or_decrement_links(node_to_rm) &&
		!fs_save_inode(cwd_node) &&
		!fs_transaction_commit(&transaction) ? 0 : -1;
	}

cleanup:
	if (node_to_rm)
		kfree(node_to_rm);
	if (cwd_node)
		kfree(cwd_node);
	if (cwd_record_list)
		fs_dir_dealloc(cwd_record_list);
	return ret;
}

int fs_link(char *filename, char *new_filename)
{
	struct fs_inode *cwd_node = fs_get_inode(cwd), *node_to_access = 0;
	struct fs_dir_record_list *cwd_record_list = fs_readdir(cwd_node);
	struct fs_dir_record *new_record = 0;
	int ret = -1;

	fs_transaction_init(&transaction);

	if (!cwd_record_list || !cwd_node) {
		ret = -1;
		goto cleanup;
	}

	node_to_access = fs_lookup_dir_node(filename, cwd_record_list);
	new_record = fs_init_record_by_filename(new_filename, node_to_access);

	if (node_to_access && new_record)
		ret = !fs_dir_add(cwd_record_list, new_record, cwd_node) &&
			!fs_writedir(cwd_node, cwd_record_list) &&
			!fs_save_inode(cwd_node) &&
			!fs_save_inode(node_to_access) &&
			!fs_transaction_commit(&transaction) ? 0 : -1;

cleanup:
	if (node_to_access)
		kfree(node_to_access);
	if (cwd_node)
		kfree(cwd_node);
	if (new_record)
		kfree(new_record);
	if (cwd_record_list)
		fs_dir_dealloc(cwd_record_list);
	return ret;
}

int fs_init(void)
{
	bool formatted;
	cwd = 1;
	memset(&table, 0, sizeof(struct fdtable));
	if (fs_ata_init(&formatted) < 0)
		return -1;
	super = fs_ata_get_superblock();
	if (!super || fs_transactions_init(super) < 0)
		return -1;
	return formatted || !fs_mkfs() ? 0 : -1;
}

int fs_stat(char *filename, struct fs_stat *stat)
{
	struct fs_inode *cwd_node = fs_get_inode(cwd), *node = 0;
	struct fs_dir_record_list *cwd_record_list = fs_readdir(cwd_node);
	int ret = -1;
	if (!cwd_node || !cwd_record_list) {
		goto cleanup;
	}
	node = fs_lookup_dir_node(filename, cwd_record_list);
	if (node) {
		stat->inode_number = node->inode_number;
		stat->is_directory = node->is_directory;
		stat->size = node->sz;
		stat->links = node->link_count;
		stat->num_blocks = node->direct_addresses_len;
		ret = 0;
	}
cleanup:
	if (node)
		kfree(node);
	if (cwd_node)
		kfree(cwd_node);
	if (cwd_record_list)
		fs_dir_dealloc(cwd_record_list);
	return ret;
}

int fs_lseek(int fd, uint32_t n)
{
	struct fdtable_entry *entry = fdtable_get(&table, fd);
	if (!entry)
		return -1;
	fdtable_entry_seek_absolute(entry, n);
	return 0;
}

int fs_mkfs(void)
{
	struct fs_dir_record_list *top_dir;
	struct fs_inode *first_node;
	bool is_directory = 1;
	int ret = 0;

	fs_transaction_init(&transaction);
	first_node = fs_create_new_inode(is_directory);
	top_dir = fs_create_empty_dir(first_node);

	if (first_node && top_dir) {
		if (!fs_writedir(first_node, top_dir) &&
				!fs_save_inode(first_node))
			ret = fs_transaction_commit(&transaction);
	}

	if (first_node)
		kfree(first_node);
	if (top_dir)
		fs_dir_dealloc(top_dir);
	return ret;
}
