/*
Copyright (C) 2017 The University of Notre Dame
This software is distributed under the GNU General Public License.
See the file LICENSE for details.
*/

#include "../kerneltypes.h"
#include "../ata.h"
#include "../kmalloc.h"
#include "kevinfs.h"
#include "kevinfs_ata.h"
#include "../string.h"
#include "../hashtable.h"
#include "../fs.h"

static uint32_t ceiling(double d)
{
    uint32_t i = (uint32_t) d;
    if (d == (double) i)
	    return i;
    return i + 1;
}

struct kevinfs_volume {
       uint32_t unit;
       int root_inode_num;
       struct kevinfs_superblock *super;
};

struct kevinfs_dirent {
       struct kevinfs_volume *kv;
       struct kevinfs_inode *node;
};

struct kevinfs_file {
	struct kevinfs_inode *node;
	uint32_t offset;
	uint8_t mode;
};

static struct kevinfs_volume *kevinfs_superblock_as_kevinfs_volume(struct kevinfs_superblock *s, uint32_t unit);
static struct volume *kevinfs_volume_as_volume(struct kevinfs_volume *kv);
static struct dirent *kevinfs_dirent_as_dirent(struct kevinfs_dirent *kd);
static struct file *kevinfs_file_as_file(struct kevinfs_file *kf, struct dirent *d);
static struct kevinfs_dirent *kevinfs_inode_as_kevinfs_dirent(struct kevinfs_volume *v, struct kevinfs_inode *node);
static struct kevinfs_volume *kevinfs_volume_create_empty(uint32_t unit_no);

static struct kevinfs_file *kevinfs_file_init(struct kevinfs_inode *node, uint8_t mode){
	struct kevinfs_file *res = kmalloc(sizeof(struct kevinfs_file));
	res->offset = 0;
	res->mode = mode;
	res->node = node;
	return res;
}

static void kevinfs_print_superblock(struct kevinfs_superblock *s)
{
	printf("fs: magic: %u, blocksize: %u, free_blocks: %u, inode_count: %u, inode_bitmap_start: %u, inode_start: %u, block_bitmap_start: %u, free_block_start: %u \n",
			s->magic,
			s->blocksize,
			s->num_free_blocks,
			s->num_inodes,
			s->inode_bitmap_start,
			s->inode_start,
			s->block_bitmap_start,
			s->free_block_start);
}

static void kevinfs_print_inode(struct kevinfs_inode *n)
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

static void kevinfs_print_dir_record(struct kevinfs_dir_record *d)
{
	printf("fs: filename: %s, inode_number: %u, offset: %d\n",
			d->filename,
			d->inode_number,
			d->offset_to_next);
}

static void kevinfs_print_dir_record_list(struct kevinfs_dir_record_list *l)
{
	uint32_t i;
	for (i = 0; i < l->list_len; i++) {
		kevinfs_print_dir_record(l->list + i);
	}
}

static int kevinfs_get_available_block(struct kevinfs_volume *kv, uint32_t *index)
{
	struct kevinfs_superblock *super = kv->super;
	int res = kevinfs_ata_ffs_range(kv->unit, super->block_bitmap_start, super->free_block_start, index);
	if (res < 0) return res;
	return kevinfs_ata_set_bit(kv->unit, *index, super->block_bitmap_start, super->free_block_start);
}

static int kevinfs_get_available_inode(struct kevinfs_volume *kv, uint32_t *index)
{
	struct kevinfs_superblock *super = kv->super;
	int res = kevinfs_ata_ffs_range(kv->unit, super->inode_bitmap_start, super->inode_start, index);
	if (res < 0) return res;
	*index += 1;
	return kevinfs_ata_set_bit(kv->unit, *index-1 , super->inode_bitmap_start, super->inode_start);
}

static int kevinfs_do_delete_dirent(struct kevinfs_dirent *kd)
{
	struct kevinfs_inode *node = kd->node;
	struct kevinfs_volume *kv = kd->kv;
	struct kevinfs_superblock *super = kv->super;
	uint32_t index = node->inode_number;

	if (kevinfs_ata_unset_bit(kv->unit, index, super->inode_bitmap_start, super->inode_start) < 0)
		return -1;

	return 0;
}

static int kevinfs_do_save_dirent(struct kevinfs_dirent *kd)
{
	struct kevinfs_inode *node = kd->node;
	struct kevinfs_volume *kv = kd->kv;
	struct kevinfs_superblock *super = kv->super;
	uint32_t index = node->inode_number - 1;
	uint32_t inodes_per_block = FS_BLOCKSIZE / sizeof(struct kevinfs_inode);
	uint32_t block = index / inodes_per_block;
	uint32_t offset = index % inodes_per_block;
	struct kevinfs_inode current_nodes[inodes_per_block];
	bool is_valid;

	if (kevinfs_ata_check_bit(kv->unit, index, super->block_bitmap_start, super->free_block_start, &is_valid) < 0 || !is_valid)
		return -1;
	if (kevinfs_ata_read_block(kv->unit, super->inode_start + block, current_nodes) < 0)
		return -1;
	memcpy(current_nodes + offset, node, sizeof(struct kevinfs_inode));
	if (kevinfs_ata_write_block(kv->unit, super->inode_start + block, current_nodes) < 0)
		return -1;

	return 0;
}

static int kevinfs_do_delete_data(struct kevinfs_volume *kv, uint32_t index)
{
	struct kevinfs_superblock *super = kv->super;
	if (kevinfs_ata_unset_bit(kv->unit, index, super->block_bitmap_start, super->free_block_start) < 0) {
		return -1;
	}
	return 0;
}

static int kevinfs_do_save_data(struct kevinfs_volume *kv, char *buffer, uint32_t index)
{
	bool is_valid;
	struct kevinfs_superblock *super = kv->super;

	if (kevinfs_ata_check_bit(kv->unit, index, super->block_bitmap_start, super->free_block_start, &is_valid) < 0 || !is_valid)
		return -1;

	return kevinfs_ata_write_block(kv->unit, super->free_block_start + index, buffer);
}

static struct kevinfs_inode *kevinfs_create_new_inode(struct kevinfs_volume *kv, bool is_directory)
{
	struct kevinfs_inode *node;
	uint32_t inode_number;

	if (kevinfs_get_available_inode(kv, &inode_number) < 0)
		return 0;

	node = kmalloc(sizeof(struct kevinfs_inode));
	if (!node)
		return 0;

	memset(node, 0, sizeof(struct kevinfs_inode));
	node->inode_number = inode_number;
	node->is_directory = is_directory;
	node->link_count = is_directory ? 1 : 0;

	return node;
}

static struct kevinfs_inode *kevinfs_get_inode(struct kevinfs_volume *kv, uint32_t inode_number)
{
	uint8_t buffer[FS_BLOCKSIZE];
	struct kevinfs_superblock *super = kv->super;
	struct kevinfs_inode *node;
	uint32_t index = inode_number - 1;
	uint32_t inodes_per_block = FS_BLOCKSIZE / sizeof(struct kevinfs_inode);
	uint32_t block = index / inodes_per_block;
	uint32_t offset = (index % inodes_per_block) * sizeof(struct kevinfs_inode);
	bool is_active;

	if (kevinfs_ata_check_bit(kv->unit, index, super->inode_bitmap_start, super->inode_start, &is_active) < 0)
		return 0;
	if (is_active == 0)
		return 0;

	node = kmalloc(sizeof(struct kevinfs_inode));
	if (node) {
		if (kevinfs_ata_read_block(kv->unit, super->inode_start + block, buffer) < 0) {
			kfree(node);
			node = 0;
		}
		else {
			memcpy(node, buffer + offset, sizeof(struct kevinfs_inode));
		}
	}

	return node;
}

static int kevinfs_save_dirent(struct kevinfs_dirent *kd)
{
	return kevinfs_do_save_dirent(kd);
}

//static int kevinfs_delete_data_block(uint32_t index, uint8_t *buffer)
//{
//	return kevinfs_transaction_stage_data(&transaction, index, buffer, FS_TRANSACTION_DELETE);
//}
//
//static int kevinfs_delete_inode_or_decrement_links(struct kevinfs_inode *node)
//{
//       uint32_t i;
//       if (node->is_directory)
//	       node->link_count--;
//       node->link_count--;
//       if (node->link_count > 0)
//	       return kevinfs_transaction_stage_inode(&transaction, node, FS_TRANSACTION_MODIFY);
//       if (kevinfs_transaction_stage_inode(&transaction, node, FS_TRANSACTION_DELETE) < 0)
//	       return -1;
//       for (i = 0; i < node->direct_addresses_len; i++) {
//	       if (kevinfs_delete_data_block(node->direct_addresses[i], 0) < 0)
//		       return -1;
//       }
//       return 0;
//}
//
static int kevinfs_write_data_block(struct kevinfs_volume *kv, uint32_t index, uint8_t *buffer)
{
	struct kevinfs_superblock *super = kv->super;
	return kevinfs_ata_write_block(kv->unit, super->free_block_start + index, buffer);
}

static int kevinfs_read_data(struct kevinfs_volume *kv, uint32_t index, uint8_t *buffer)
{
	bool is_active;
	struct kevinfs_superblock *super = kv->super;
	if (kevinfs_ata_check_bit(kv->unit, index, super->block_bitmap_start, super->free_block_start, &is_active) < 0) {
		return -1;
	}
	if (is_active == 0) {
		return -1;
	}
	return kevinfs_ata_read_block(kv->unit, super->free_block_start + index, buffer);
}

static struct kevinfs_dir_record_list *kevinfs_dir_alloc(uint32_t list_len)
{
	struct kevinfs_dir_record_list *ret = kmalloc(sizeof(struct kevinfs_dir_record_list));
	if (ret)
		ret->changed = hash_set_init(19);
		ret->list_len = list_len;
		ret->list = kmalloc(sizeof(struct kevinfs_dir_record) * list_len);
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

static void kevinfs_dir_dealloc(struct kevinfs_dir_record_list *dir_list)
{
	kfree(dir_list->list);
	hash_set_dealloc(dir_list->changed);
	kfree(dir_list);
}

static struct kevinfs_dir_record_list *kevinfs_readdir(struct kevinfs_dirent *kd)
{
	struct kevinfs_inode *node = kd->node;
	struct kevinfs_volume *kv = kd->kv;
	uint8_t buffer[FS_BLOCKSIZE * node->direct_addresses_len];
	uint32_t num_files = node->sz / sizeof(struct kevinfs_dir_record);
	struct kevinfs_dir_record_list *res = kevinfs_dir_alloc(num_files);
	struct kevinfs_dir_record *files = res->list;

	if (!res)
		return 0;

	uint32_t i;
	for (i = 0; i < node->direct_addresses_len; i++) {
		if (kevinfs_read_data(kv, node->direct_addresses[i], buffer + i * FS_BLOCKSIZE) < 0) {
			kevinfs_dir_dealloc(res);
			return 0;
		}
	}

	for (i = 0; i < num_files; i++) {
		memcpy(&files[i], buffer + sizeof(struct kevinfs_dir_record) * i, sizeof(struct kevinfs_dir_record));
	}

	return res;
}

static int kevinfs_read_dir(struct dirent *d, char *buffer, int buffer_len)
{
	struct kevinfs_dirent *kd = d->private_data;
	struct kevinfs_dir_record_list *list = kevinfs_readdir(kd);
	int ret = kd && list ? 0 : -1;
	int total = 0;

	if (list) {
		struct kevinfs_dir_record *r = list->list;
		while (buffer_len > strlen(r->filename)) {
			int len = strlen(r->filename);
			strcpy(buffer, r->filename);
			buffer += len;
			*buffer = ' ';
			buffer++;
			buffer_len -= len+1;
			total += len+1;

			if (r->offset_to_next == 0)
				break;
			r += r->offset_to_next;
		}
		kevinfs_dir_dealloc(list);
	}
	return ret < 0 ? ret : total;
}

//static void kevinfs_printdir_inorder(struct kevinfs_dir_record_list *dir_list)
//{
//	struct kevinfs_dir_record *files = dir_list->list;
//	while (1) {
//		printf("%s\n", files->filename);
//		if (files->offset_to_next == 0)
//			return;
//		files += files->offset_to_next;
//	}
//}

static int kevinfs_dirent_resize(struct kevinfs_dirent *kd, uint32_t num_blocks)
{
	uint32_t i;
	struct kevinfs_volume *kv = kd->kv;
	struct kevinfs_inode *node = kd->node;
	if (num_blocks > FS_INODE_MAXBLOCKS)
		return -1;
	for (i = node->direct_addresses_len; i < num_blocks; i++){
		if (kevinfs_get_available_block(kv, &(node->direct_addresses[i])) < 0) {
			return -1;
		}
	}
	for (i = node->direct_addresses_len; i > num_blocks; i--) {
		if (kevinfs_do_delete_data(kv, node->direct_addresses[i-1]) < 0) {
			return -1;
		}
		node->direct_addresses[i-1] = 0;
	}
	node->direct_addresses_len = num_blocks;
	return 0;
}

static struct kevinfs_dir_record *kevinfs_lookup_dir_prev(char *filename, struct kevinfs_dir_record_list *dir_list)
{
	struct kevinfs_dir_record *iter = dir_list->list, *prev = 0;
	while (strcmp(iter->filename, filename) < 0) {
		prev = iter;
		if (iter->offset_to_next == 0)
			break;
		iter += iter->offset_to_next;
	}
	return prev;
}

//static struct kevinfs_dir_record *kevinfs_lookup_dir_exact(char *filename, struct kevinfs_dir_record_list *dir_list)
//{
//	struct kevinfs_dir_record *iter = dir_list->list, *prev = 0;
//	while (strcmp(iter->filename, filename) <= 0) {
//		prev = iter;
//		if (iter->offset_to_next == 0)
//			break;
//		iter += iter->offset_to_next;
//	}
//	return (strcmp(prev->filename, filename) == 0) ? prev : 0;
//}
//
//static struct kevinfs_inode *kevinfs_lookup_dir_node(char *filename, struct kevinfs_dir_record_list *dir_list)
//{
//	struct kevinfs_dir_record *res = kevinfs_lookup_dir_exact(filename, dir_list);
//	return res ? kevinfs_get_inode(res->inode_number) : 0;
//}
//
//static struct dirent *kevinfs_dirent_lookup(struct dirent *d, char *name)
//{
//	struct kevinfs_inode *node = d->private_data;
//	struct kevinfs_dir_record_list *dir_list = kevinfs_readdir(node);
//	struct kevinfs_inode *res = dir_list ? kevinfs_lookup_dir_node(name, dir_list) : 0;
//	return res ? kevinfs_inode_as_dirent(res) : 0;
//}
//
//

static int kevinfs_dir_record_insert_after(struct kevinfs_dir_record_list *dir_list,
		struct kevinfs_dir_record *prev,
		struct kevinfs_dir_record *new)
{
	struct kevinfs_dir_record *list = dir_list->list;
	struct kevinfs_dir_record *new_list;
	struct kevinfs_dir_record *new_pos, *new_prev;

	new_list = kmalloc((dir_list->list_len + 1) * sizeof(struct kevinfs_dir_record));
	memcpy(new_list, list, dir_list->list_len * sizeof(struct kevinfs_dir_record));
	new_pos = new_list + dir_list->list_len;
	new_prev = new_list + (prev - list);

	if (prev) {
		memcpy(new_pos, new, sizeof(struct kevinfs_dir_record));
		if (prev->offset_to_next != 0)
			new_pos->offset_to_next = new_prev + new_prev->offset_to_next - new_pos;
		else
			new_pos->offset_to_next = 0;

		new_prev->offset_to_next = new_pos - new_prev;
		hash_set_add(dir_list->changed, (new_prev - new_list) * sizeof(struct kevinfs_dir_record) / FS_BLOCKSIZE);
		hash_set_add(dir_list->changed, ((new_prev - new_list + 1) * sizeof(struct kevinfs_dir_record) - 1) / FS_BLOCKSIZE);
	}
	else {
		memcpy(new_pos, new_list, sizeof(struct kevinfs_dir_record));
		new_pos->offset_to_next = new_pos - new_list;
		memcpy(new_list, new, sizeof(struct kevinfs_dir_record));
		new_list->offset_to_next = new_list - new_pos;

		hash_set_add(dir_list->changed, 0);
		hash_set_add(dir_list->changed, (sizeof(struct kevinfs_dir_record) - 1)/FS_BLOCKSIZE);
	}
	hash_set_add(dir_list->changed, (new_pos - new_list) * sizeof(struct kevinfs_dir_record) / FS_BLOCKSIZE);
	hash_set_add(dir_list->changed, ((new_pos - new_list + 1) * sizeof(struct kevinfs_dir_record) - 1) / FS_BLOCKSIZE);

	kfree (list);
	dir_list->list = new_list;
	dir_list->list_len++;
	return 0;
}

//static int kevinfs_dir_record_rm_after(struct kevinfs_dir_record_list *dir_list,
//		struct kevinfs_dir_record *prev)
//{
//	struct kevinfs_dir_record *to_rm, *next, *last, *last_prev, *list_head;
//	bool is_removing_end;
//
//	list_head = dir_list->list;
//	last = dir_list->list + dir_list->list_len - 1;
//	to_rm = prev + prev->offset_to_next;
//	next = to_rm + to_rm->offset_to_next;
//	last_prev = kevinfs_lookup_dir_prev(last->filename, dir_list);
//	is_removing_end = to_rm->offset_to_next == 0;
//
//	if (last != to_rm) {
//		memcpy(to_rm, last, sizeof(struct kevinfs_dir_record));
//
//		if (last == next)
//			next = to_rm;
//		if (last == prev)
//			prev = to_rm;
//
//		if (to_rm != last_prev)
//			last_prev->offset_to_next = last_prev->offset_to_next - (last - to_rm);
//		if (to_rm->offset_to_next != 0)
//			to_rm->offset_to_next = to_rm->offset_to_next + (last - to_rm);
//
//		hash_set_add(dir_list->changed, (to_rm - list_head) * sizeof(struct kevinfs_dir_record) / FS_BLOCKSIZE);
//		hash_set_add(dir_list->changed, ((to_rm - list_head + 1) * sizeof(struct kevinfs_dir_record) - 1) / FS_BLOCKSIZE);
//
//		hash_set_add(dir_list->changed, (last_prev - list_head) * sizeof(struct kevinfs_dir_record) / FS_BLOCKSIZE);
//		hash_set_add(dir_list->changed, ((last_prev - list_head + 1) * sizeof(struct kevinfs_dir_record) - 1) / FS_BLOCKSIZE);
//
//	}
//
//	if (is_removing_end)
//		prev->offset_to_next = 0;
//	else
//		prev->offset_to_next = next - prev;
//
//	memset(last, 0, sizeof(struct kevinfs_dir_record));
//
//	hash_set_add(dir_list->changed, (last - list_head) * sizeof(struct kevinfs_dir_record) / FS_BLOCKSIZE);
//	hash_set_add(dir_list->changed, ((last - list_head + 1) * sizeof(struct kevinfs_dir_record) - 1) / FS_BLOCKSIZE);
//
//	hash_set_add(dir_list->changed, (prev - list_head) * sizeof(struct kevinfs_dir_record) / FS_BLOCKSIZE);
//	hash_set_add(dir_list->changed, ((prev - list_head + 1) * sizeof(struct kevinfs_dir_record) - 1) / FS_BLOCKSIZE);
//
//	dir_list->list_len--;
//	return 0;
//}
//
static int kevinfs_dir_add(struct kevinfs_dir_record_list *current_files,
		struct kevinfs_dir_record *new_file,
		struct kevinfs_inode *parent)
{
	uint32_t len = current_files->list_len;
	struct kevinfs_dir_record *lookup, *next;

	if (len < FS_EMPTY_DIR_SIZE) {
		return -1;
	}

	lookup = kevinfs_lookup_dir_prev(new_file->filename, current_files);
	next = lookup + lookup->offset_to_next;
	if (strcmp(next->filename, new_file->filename) == 0) {
		return -1;
	}
	if (kevinfs_dir_record_insert_after(current_files, lookup, new_file) < 0)
		return -1;

	parent->link_count++;
	return 0;
}

//static int kevinfs_dir_rm(struct kevinfs_dir_record_list *current_files,
//		char *filename,
//		struct kevinfs_inode *parent)
//{
//	uint32_t len = current_files->list_len;
//	struct kevinfs_dir_record *lookup, *next;
//	struct kevinfs_inode *node;
//
//	if (len < FS_EMPTY_DIR_SIZE) {
//		return -1;
//	}
//
//	lookup = kevinfs_lookup_dir_prev(filename, current_files);
//	node = kevinfs_lookup_dir_node(filename, current_files);
//	next = lookup + lookup->offset_to_next;
//	if (node && node->is_directory && node->sz == FS_EMPTY_DIR_SIZE_BYTES && next->is_directory && strcmp(next->filename, filename) == 0) {
//		parent->link_count--;
//		return kevinfs_delete_inode_or_decrement_links(node) < 0 || kevinfs_dir_record_rm_after(current_files, lookup) < 0 ? -1 : 0;
//	}
//	if (node)
//		kfree(node);
//	return -1;
//}
//
static int kevinfs_writedir(struct kevinfs_dirent *kd, struct kevinfs_dir_record_list *files)
{
	struct kevinfs_volume *kv = kd->kv;
	struct kevinfs_inode *node = kd->node;
	uint32_t new_len = files->list_len;
	uint8_t *buffer = kmalloc(sizeof(struct kevinfs_dir_record) * new_len);
	uint32_t i, ending_index = (new_len * sizeof(struct kevinfs_dir_record) - 1) / FS_BLOCKSIZE;
	uint32_t ending_num_indices = ceiling(((double) new_len * sizeof(struct kevinfs_dir_record)) / FS_BLOCKSIZE);
	int ret = 0;

	for (i = 0; i < new_len; i++) {
		memcpy(buffer + sizeof(struct kevinfs_dir_record) * i, files->list + i, sizeof(struct kevinfs_dir_record));
	}
	if (kevinfs_dirent_resize(kd, ending_num_indices) < 0) {
		ret = -1;
		goto cleanup;
	}
	for (i = 0; i <= ending_index; i++) {
		if (hash_set_lookup(files->changed, i)) {
			ret = kevinfs_write_data_block(kv, node->direct_addresses[i], buffer + FS_BLOCKSIZE * i);
			if (ret < 0)
				goto cleanup;
		}
	}
	node->sz = new_len * sizeof(struct kevinfs_dir_record);
cleanup:
	kfree(buffer);
	return ret;
}

static struct kevinfs_dir_record_list *kevinfs_create_empty_dir(struct kevinfs_inode *node, struct kevinfs_inode *parent)
{
	struct kevinfs_dir_record_list *dir;
	struct kevinfs_dir_record *records;

	if (!node)
		return 0;

	dir = kevinfs_dir_alloc(FS_EMPTY_DIR_SIZE);
	if (!dir)
		return 0;

	records = dir->list;
	strcpy(records[0].filename, ".");
	records[0].offset_to_next = 1;
	records[0].inode_number = node->inode_number;
	records[0].is_directory = 1;
	strcpy(records[1].filename, "..");
	records[1].inode_number = parent->inode_number;
	records[1].offset_to_next = 0;
	records[1].is_directory = 1;

	hash_set_add(dir->changed, 0);
	hash_set_add(dir->changed, (sizeof(struct kevinfs_dir_record) * FS_EMPTY_DIR_SIZE - 1) / FS_BLOCKSIZE);

	return dir;
}

static struct kevinfs_dir_record *kevinfs_init_record_by_filename(const char *filename, struct kevinfs_dirent *new_dirent)
{
	uint32_t filename_len = strlen(filename);
	struct kevinfs_dir_record *record;
	struct kevinfs_inode *node = new_dirent->node;
	if (filename_len > FS_FILENAME_MAXLEN || !new_dirent) {
		return 0;
	}

	record = kmalloc(sizeof(struct kevinfs_dir_record));
	if (!record)
		return 0;

	strcpy(record->filename,filename);
	record->inode_number = node->inode_number;
	record->is_directory = node->is_directory;
	node->link_count++;
	return record;
}

//static struct kevinfs_inode *kevinfs_create_file(char *filename, struct kevinfs_dir_record_list *dir_list, struct kevinfs_inode *dir_node)
//{
//	struct kevinfs_inode *new_node;
//	struct kevinfs_dir_record *new_record, *prev, *maybe_same_name;
//	bool is_directory = 0;
//	int ret = 0;
//
//	new_node = kevinfs_create_new_inode(is_directory);
//	new_record = kevinfs_init_record_by_filename(filename, new_node);
//	prev = kevinfs_lookup_dir_prev(filename, dir_list);
//	maybe_same_name = prev + prev->offset_to_next;
//
//	if (!new_node || !new_record || !strcmp(maybe_same_name->filename, filename))
//		ret = -1;
//	else
//		ret = !kevinfs_dir_record_insert_after(dir_list, prev, new_record) &&
//			!kevinfs_writedir(dir_node, dir_list) &&
//			!kevinfs_save_inode(dir_node) ? 0 : -1;
//
//	if (new_record)
//		kfree(new_record);
//	if (ret < 0 && new_node) {
//		kfree(new_node);
//		new_node = 0;
//	}
//
//	return new_node;
//}
//
//static int kevinfs_write_file_range(struct kevinfs_inode *node, uint8_t *buffer, uint32_t start, uint32_t n)
//{
//	uint32_t direct_addresses_start = start / FS_BLOCKSIZE, direct_addresses_end = (start + n - 1) / FS_BLOCKSIZE;
//	uint32_t start_offset = start % FS_BLOCKSIZE, end_offset = (start + n - 1) % FS_BLOCKSIZE;
//	uint32_t i, total_copy_length = 0;
//
//	if (kevinfs_inode_resize(node,  direct_addresses_end + 1) < 0) {
//		return -1;
//	}
//
//	for (i = direct_addresses_start; i <= direct_addresses_end; i++) {
//		uint8_t buffer_part[FS_BLOCKSIZE];
//		uint8_t *copy_start = buffer_part;
//		uint32_t buffer_part_len = FS_BLOCKSIZE;
//		memset(buffer_part, 0, sizeof(buffer_part));
//		if (i == direct_addresses_start) {
//			copy_start += start_offset;
//		}
//		if (i == direct_addresses_end) {
//			buffer_part_len -= FS_BLOCKSIZE - end_offset;
//		}
//		memcpy(copy_start, buffer + total_copy_length, buffer_part_len);
//		if (kevinfs_write_data_block(node->direct_addresses[i], buffer_part) < 0)
//			return -1;
//		total_copy_length += buffer_part_len;
//	}
//	if (start + n > node->sz)
//		node->sz = start + n;
//	if (kevinfs_save_inode(node) < 0)
//		return -1;
//
//	return total_copy_length;
//}
//
//static int kevinfs_read_file_range(struct kevinfs_inode *node, uint8_t *buffer, uint32_t start, uint32_t n)
//{
//	uint32_t direct_addresses_start = start / FS_BLOCKSIZE, direct_addresses_end = (start + n - 1) / FS_BLOCKSIZE;
//	uint32_t start_offset = start % FS_BLOCKSIZE, end_offset = (start + n) % FS_BLOCKSIZE;
//	uint32_t i, total_copy_length = 0;
//
//	for (i = direct_addresses_start; i <= direct_addresses_end; i++) {
//		uint8_t buffer_part[FS_BLOCKSIZE];
//		uint8_t *copy_start = buffer_part;
//		uint32_t buffer_part_len = FS_BLOCKSIZE;
//		memset(buffer_part, 0, sizeof(buffer_part));
//		if (i == direct_addresses_start) {
//			copy_start += start_offset;
//		}
//		if (i == direct_addresses_end) {
//			buffer_part_len -= FS_BLOCKSIZE - end_offset - 1;
//		}
//		if (kevinfs_read_data(node->direct_addresses[i], buffer_part) < 0)
//			return -1;
//		memcpy(buffer + total_copy_length, copy_start, buffer_part_len);
//		total_copy_length += buffer_part_len;
//	}
//
//	return total_copy_length;
//}
//
static struct volume *kevinfs_mount(uint32_t unit_no)
{
	struct kevinfs_superblock *super = kevinfs_ata_read_superblock(unit_no);
	if (!super) return 0;
	struct kevinfs_volume *kv = kevinfs_superblock_as_kevinfs_volume(super, unit_no);
	struct volume *v = kevinfs_volume_as_volume(kv);
	return v;
}

static int kevinfs_mkdir(struct dirent *d, const char *filename)
{
	struct kevinfs_dir_record_list *new_dir_record_list, *cwd_record_list;
	struct kevinfs_dirent *kd = d->private_data;
	struct kevinfs_dirent *new_kd;
	struct kevinfs_volume *kv = kd->kv;
	struct kevinfs_dir_record *new_cwd_record;
	struct kevinfs_inode *new_node;
	bool is_directory = 1;
	int ret = 0;

	new_node = kevinfs_create_new_inode(kv, is_directory);
	new_kd = kevinfs_inode_as_kevinfs_dirent(kv, new_node);

	cwd_record_list = kevinfs_readdir(kd);
	new_dir_record_list = kevinfs_create_empty_dir(new_node, kd->node);
	new_cwd_record = kevinfs_init_record_by_filename(filename, new_kd);

	if (!kd|| !new_kd || !cwd_record_list ||
			!new_dir_record_list || !new_cwd_record) {
		ret = -1;
		goto cleanup;
	}

	if (kevinfs_writedir(new_kd, new_dir_record_list) < 0 ||
		kevinfs_dir_add(cwd_record_list, new_cwd_record, kd->node) < 0 ||
		kevinfs_writedir(kd, cwd_record_list) < 0 ||
		kevinfs_save_dirent(new_kd) < 0 ||
		kevinfs_save_dirent(kd) < 0) {
		ret = -1;
		goto cleanup;
	}

cleanup:
	if (new_dir_record_list)
		kevinfs_dir_dealloc(new_dir_record_list);
	if (cwd_record_list)
		kevinfs_dir_dealloc(cwd_record_list);
	if (new_cwd_record)
		kfree(new_cwd_record);
	if (new_node)
		kfree(new_node);
	return ret;
}

//static int kevinfs_mkfile(struct dirent *d, const char *filename)
//{
//	struct kevinfs_dir_record_list *new_dir_record_list, *cwd_record_list;
//	struct kevinfs_dir_record *new_cwd_record;
//	struct kevinfs_inode *new_node, *cwd_node;
//	bool is_directory = 0;
//	int ret = 0;
//
//	kevinfs_transaction_init(&transaction);
//
//	new_node = kevinfs_create_new_inode(is_directory);
//	cwd_node = d->private_data;
//	cwd_record_list = kevinfs_readdir(cwd_node);
//	new_dir_record_list = kevinfs_create_empty_dir(new_node, cwd_node);
//	new_cwd_record = kevinfs_init_record_by_filename(filename, new_node);
//
//	if (!new_node || !cwd_node || !cwd_record_list ||
//			!new_dir_record_list || !new_cwd_record) {
//		ret = -1;
//		goto cleanup;
//	}
//
//	if (kevinfs_writedir(new_node, new_dir_record_list) < 0 ||
//		kevinfs_dir_add(cwd_record_list, new_cwd_record, cwd_node) < 0 ||
//		kevinfs_writedir(cwd_node, cwd_record_list) < 0 ||
//		kevinfs_save_inode(new_node) < 0 ||
//		kevinfs_save_inode(cwd_node) < 0) {
//		ret = -1;
//		goto cleanup;
//	}
//
//	ret = kevinfs_transaction_commit(&transaction);
//
//cleanup:
//	if (new_dir_record_list)
//		kevinfs_dir_dealloc(new_dir_record_list);
//	if (cwd_record_list)
//		kevinfs_dir_dealloc(cwd_record_list);
//	if (new_cwd_record)
//		kfree(new_cwd_record);
//	if (new_node)
//		kfree(new_node);
//	return ret;
//}
//
//static int kevinfs_rmdir(struct dirent *d, const char *filename)
//{
//	struct kevinfs_dir_record_list *cwd_record_list;
//	struct kevinfs_inode *cwd_node = d->private_data;
//	int ret = -1;
//
//	kevinfs_transaction_init(&transaction);
//
//	cwd_record_list = kevinfs_readdir(cwd_node);
//
//	if (cwd_node && cwd_record_list) {
//		ret = !kevinfs_dir_rm(cwd_record_list, filename, cwd_node) &&
//			!kevinfs_writedir(cwd_node, cwd_record_list) &&
//			!kevinfs_save_inode(cwd_node) &&
//			!kevinfs_transaction_commit(&transaction) ? 0 : -1;
//	}
//
//	if (cwd_record_list)
//		kevinfs_dir_dealloc(cwd_record_list);
//
//	return ret;
//}
//
//static struct file *kevinfs_open(struct dirent *d, uint8_t mode)
//{
//	struct kevinfs_inode *node_to_access;
//	int ret = -1;
//
//	kevinfs_transaction_init(&transaction);
//
//	node_to_access = d->private_data;
//
//	if (node_to_access)
//		ret = !kevinfs_transaction_commit(&transaction) ? 0 : -1;
//
//cleanup:
//	if (ret == 0) {
//		struct kevinfs_file *kf = kevinfs_file_init(node_to_access, mode);
//		return kevinfs_file_as_file(kf, d);
//	}
//	return 0;
//}
//
//static int kevinfs_close(struct file *f)
//{
//	struct kevinfs_file *kf = f->private_data;
//	kfree(kf);
//	return 0;
//}
//
//static int kevinfs_write(struct file *f, uint8_t *buffer, uint32_t n)
//{
//	struct kevinfs_file *kf = f->private_data;
//	uint32_t original_offset = kf->offset, new_offset;
//
//	kevinfs_transaction_init(&transaction);
//	if (!kf || !(FILE_MODE_WRITE & kf->mode))
//		return -1;
//	kf->offset += n;
//	if (kf->offset >= FS_INODE_MAXBLOCKS * FS_BLOCKSIZE)
//		return -1;
//
//	new_offset = kf->offset;
//	if (kevinfs_write_file_range(kf->inode, buffer, original_offset, new_offset - original_offset) < 0 ||
//			kevinfs_transaction_commit(&transaction) < 0)
//		return -1;
//
//	return new_offset - original_offset;
//}
//
//static int kevinfs_read(struct file *f, uint8_t *buffer, uint32_t n)
//{
//	struct kevinfs_file *kf = f->private_data;
//	struct kevinfs_inode *inode = kf->inode;
//	uint32_t original_offset = kf->offset, new_offset;
//
//	if (!kf || !(FILE_MODE_READ & kf->mode))
//		return -1;
//
//	kf->offset += n;
//	if (kf->offset >= inode->sz)
//		kf->offset = inode->sz;
//
//	new_offset = kf->offset;
//	if (new_offset == original_offset ||
//			kevinfs_read_file_range(kf->inode, buffer, original_offset, new_offset - original_offset) < 0)
//		return -1;
//	return new_offset - original_offset;
//}
//
//static int kevinfs_unlink(struct dirent *d, char *filename)
//{
//	struct kevinfs_inode *cwd_node = d->private_data, *node_to_rm = 0;
//	struct kevinfs_dir_record_list *cwd_record_list = kevinfs_readdir(cwd_node);
//	struct kevinfs_dir_record *prev;
//	uint8_t ret = -1;
//
//	kevinfs_transaction_init(&transaction);
//
//	if (!cwd_node || !cwd_record_list)
//		goto cleanup;
//
//	node_to_rm = kevinfs_lookup_dir_node(filename, cwd_record_list);
//	prev = kevinfs_lookup_dir_prev(filename, cwd_record_list);
//
//	if (node_to_rm) {
//		ret = !kevinfs_dir_record_rm_after(cwd_record_list, prev) &&
//		!kevinfs_writedir(cwd_node, cwd_record_list) &&
//		!kevinfs_delete_inode_or_decrement_links(node_to_rm) &&
//		!kevinfs_save_inode(cwd_node) &&
//		!kevinfs_transaction_commit(&transaction) ? 0 : -1;
//	}
//
//cleanup:
//	if (node_to_rm)
//		kfree(node_to_rm);
//	if (cwd_record_list)
//		kevinfs_dir_dealloc(cwd_record_list);
//	return ret;
//}
//
//static int kevinfs_link(struct dirent *d, char *filename, char *new_filename)
//{
//	struct kevinfs_inode *cwd_node = d->private_data, *node_to_access = 0;
//	struct kevinfs_dir_record_list *cwd_record_list = kevinfs_readdir(cwd_node);
//	struct kevinfs_dir_record *new_record = 0;
//	int ret = -1;
//
//	kevinfs_transaction_init(&transaction);
//
//	if (!cwd_record_list || !cwd_node) {
//		goto cleanup;
//	}
//
//	node_to_access = kevinfs_lookup_dir_node(filename, cwd_record_list);
//	new_record = kevinfs_init_record_by_filename(new_filename, node_to_access);
//
//	if (node_to_access && !node_to_access->is_directory && new_record)
//		ret = !kevinfs_dir_add(cwd_record_list, new_record, cwd_node) &&
//			!kevinfs_writedir(cwd_node, cwd_record_list) &&
//			!kevinfs_save_inode(cwd_node) &&
//			!kevinfs_save_inode(node_to_access) &&
//			!kevinfs_transaction_commit(&transaction) ? 0 : -1;
//
//cleanup:
//	if (node_to_access)
//		kfree(node_to_access);
//	if (cwd_node)
//		kfree(cwd_node);
//	if (new_record)
//		kfree(new_record);
//	if (cwd_record_list)
//		kevinfs_dir_dealloc(cwd_record_list);
//	return ret;
//}

//int kevinfs_stat(char *filename, struct kevinfs_stat *stat)
//{
//	struct kevinfs_inode *cwd_node = kevinfs_get_inode(cwd), *node = 0;
//	struct kevinfs_dir_record_list *cwd_record_list = kevinfs_readdir(cwd_node);
//	int ret = -1;
//	if (!cwd_node || !cwd_record_list) {
//		goto cleanup;
//	}
//	node = kevinfs_lookup_dir_node(filename, cwd_record_list);
//	if (node) {
//		stat->inode_number = node->inode_number;
//		stat->is_directory = node->is_directory;
//		stat->size = node->sz;
//		stat->links = node->link_count;
//		stat->num_blocks = node->direct_addresses_len;
//		ret = 0;
//	}
//cleanup:
//	if (node)
//		kfree(node);
//	if (cwd_node)
//		kfree(cwd_node);
//	if (cwd_record_list)
//		kevinfs_dir_dealloc(cwd_record_list);
//	return ret;
//}

//int kevinfs_lseek(int fd, uint32_t n)
//{
//	struct fdtable_entry *entry = fdtable_get(&table, fd);
//	if (!entry)
//		return -1;
//	return fdtable_entry_seek_absolute(entry, n);
//}


static int kevinfs_mkfs(uint32_t unit_no)
{
	struct kevinfs_dir_record_list *top_dir;
	struct kevinfs_inode *first_node;
	struct kevinfs_volume *kv = kevinfs_volume_create_empty(unit_no);
	struct kevinfs_dirent *kd;
	bool is_directory = 1;
	int ret = -1;

	if (kevinfs_ata_format(unit_no) < 0) return -1;
	kv->root_inode_num = 1;
	kv->super = kevinfs_ata_read_superblock(unit_no);

	first_node = kevinfs_create_new_inode(kv, is_directory);
	top_dir = kevinfs_create_empty_dir(first_node, first_node);
	kd = kevinfs_inode_as_kevinfs_dirent(kv, first_node);

	if (kd && top_dir) {
		ret = !kevinfs_writedir(kd, top_dir) && !kevinfs_save_dirent(kd);
	}

	if (kd)
		kfree(kd);
	if (kv)
		kfree(kv);
	if (first_node)
		kfree(first_node);
	if (top_dir)
		kevinfs_dir_dealloc(top_dir);
	return ret;
}

static int kevinfs_register()
{
	char kevin_name[] = "kevin";
	char *kevin_name_cpy = kmalloc(6);
	struct fs f;
	strcpy(kevin_name_cpy, kevin_name);
	f.mount = kevinfs_mount;
	f.mkfs = kevinfs_mkfs;
	f.name = kevin_name_cpy;
	fs_register(&f);
	return 0;
}

int kevinfs_init(void)
{
	kevinfs_register();
	return 0;
}

static struct kevinfs_dirent *kevinfs_inode_as_kevinfs_dirent(struct kevinfs_volume *kv, struct kevinfs_inode *node)
{
	if (!node) return 0;
	struct kevinfs_dirent *kd = kmalloc(sizeof(struct kevinfs_dirent));
	kd->kv = kv;
	kd->node = node;
	return kd;
}

static struct dirent *kevinfs_root(struct volume *v)
{
	struct kevinfs_volume *kv = v->private_data;
	struct kevinfs_inode *node = kevinfs_get_inode(kv, kv->root_inode_num);
	struct kevinfs_dirent *kd = kevinfs_inode_as_kevinfs_dirent(kv, node);
	return kd ? kevinfs_dirent_as_dirent(kd) : 0;
}

//static int kevinfs_umount(struct volume *v)
//{
//	struct kevinfs_volume *kv = v->private_data;
//	struct kevinfs_inode *node = kevinfs_get_inode(kv->root_inode_num);
//	kfree(node);
//	kfree(kv);
//	return 0;
//}
//
static struct fs_volume_ops kevinfs_volume_ops = {
//	.umount = kevinfs_umount,
	.root = kevinfs_root
};

static struct fs_dirent_ops kevinfs_dirent_ops = {
	.readdir = kevinfs_read_dir,
	.mkdir = kevinfs_mkdir,
//	.mkfile = kevinfs_mkfile,
//	.lookup = kevinfs_dirent_lookup,
//	.rmdir = kevinfs_rmdir,
//	.open = kevinfs_open,
//	.unlink = kevinfs_unlink,
//	.link = kevinfs_link
};

//static struct fs_file_ops kevinfs_file_ops = {
//	.close = kevinfs_close,
//	.read = kevinfs_read,
//	.write = kevinfs_write
//};

static struct kevinfs_volume *kevinfs_superblock_as_kevinfs_volume(struct kevinfs_superblock *super, uint32_t unit_no)
{
	struct kevinfs_volume *kv = kmalloc(sizeof(struct kevinfs_volume));
	kv->root_inode_num = 1;
	kv->unit = unit_no;
	kv->super = super;
	return kv;
}

static struct kevinfs_volume *kevinfs_volume_create_empty(uint32_t unit_no)
{
	struct kevinfs_volume *kv = kmalloc(sizeof(struct kevinfs_volume));
	kv->unit = unit_no;
	return kv;
}

static struct volume *kevinfs_volume_as_volume(struct kevinfs_volume *kv)
{
	struct volume *v = kmalloc(sizeof(struct volume));
	v->private_data = kv;
	v->ops = &kevinfs_volume_ops;
	return v;
}

static struct dirent *kevinfs_dirent_as_dirent(struct kevinfs_dirent *kd)
{
	struct dirent *d = kmalloc(sizeof(struct dirent));
	d->private_data = kd;
	d->sz = kd->node->sz;
	d->ops = &kevinfs_dirent_ops;
	return d;
}

//static struct file *kevinfs_file_as_file(struct kevinfs_file *kf, struct dirent *d)
//{
//	struct file *f = kmalloc(sizeof(struct file));
//	f->private_data = kf;
//	f->sz = f->sz;
//	f->ops = &kevinfs_file_ops;
//	return f;
//}