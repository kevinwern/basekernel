#include "string.h"
#include "fs_ata.h"
#include "fs.h"
#include "kmalloc.h"

#include "fs_transaction.h"

static struct fs_superblock s;

static void fs_commit_list_append(struct fs_commit_list *list, struct fs_commit_list_entry *entry)
{
	struct fs_commit_list_entry *current = list->head, *prev = 0;
	while (current && !(entry->data_type == current->data_type && entry->number == current->number)) {
		prev = current;
		current = current->next;
	}
	if (prev) {
		prev->next = entry;
		entry->prev = prev;
	}
	else {
		list->head = entry;
	}
	if (current) {
		if (entry->op == FS_COMMIT_MODIFY && current->op == FS_COMMIT_CREATE)
			entry->op = FS_COMMIT_CREATE;
		entry->next = current->next;
		kfree(current);
		entry->next->prev = entry;
	}
}

static int fs_do_delete_inode(struct fs_commit_list_entry *entry)
{
	uint32_t inode_number = entry->number;
	uint32_t index = inode_number - 1;

	if (fs_ata_unset_bit(index, s.inode_bitmap_start, s.inode_start) < 0)
		return -1;

	entry->op = FS_COMMIT_CREATE;
	entry->is_completed = 1;
	memset(&entry->data.node, 0, sizeof(struct fs_inode));

	return 0;
}

static int fs_do_save_inode(struct fs_commit_list_entry *entry)
{
	struct fs_inode temp;
	uint8_t buffer[FS_BLOCKSIZE];
	uint32_t index = entry->number - 1;
	uint32_t inodes_per_block = FS_BLOCKSIZE / sizeof(struct fs_inode);
	uint32_t block = index / inodes_per_block;
	uint32_t offset = (index % inodes_per_block) * sizeof(struct fs_inode);

	if (entry->op == FS_COMMIT_CREATE) {
		if (fs_ata_set_bit(index, s.inode_bitmap_start, s.inode_start) < 0) {
			return -1;
		}
		entry->op = FS_COMMIT_DELETE;
		entry->is_completed = 1;
	}

	if (entry->data.node.inode_number) {
		if (fs_ata_read_block(s.inode_start + block, buffer) < 0)
			return -1;
		memcpy(&temp, buffer + offset, sizeof(struct fs_inode));
		memcpy(buffer + offset, &entry->data.node, sizeof(struct fs_inode));
		if (fs_ata_write_block(s.inode_start + block, buffer) < 0)
			return -1;
		entry->data.node = temp;
		entry->is_completed = 1;
	}

	return 0;
}

static int fs_do_delete_data(struct fs_commit_list_entry *entry)
{
	uint32_t index = entry->number;

	if (fs_ata_unset_bit(index, s.block_bitmap_start, s.free_block_start) < 0) {
		return -1;
	}

	entry->op = FS_COMMIT_CREATE;
	entry->is_completed = 1;
	return 0;
}

static int fs_do_save_data(struct fs_commit_list_entry *entry)
{
	uint32_t index = entry->number;
	uint8_t temp[FS_BLOCKSIZE];
	bool is_valid;


	if (entry->op == FS_COMMIT_CREATE) {
		if (fs_ata_set_bit(index, s.block_bitmap_start, s.free_block_start) < 0) {
			return -1;
		}
		entry->op = FS_COMMIT_DELETE;
		entry->is_completed = 1;
	}
	else if (fs_ata_check_bit(index, s.block_bitmap_start, s.free_block_start, &is_valid) < 0 || !is_valid)
		return -1;


	memcpy(temp, entry->data.to_write, sizeof(temp));
	if (fs_ata_write_block(s.free_block_start + index, temp) < 0)
		return -1;
	entry->is_completed = 1;

	return 0;
}

int fs_transactions_init(struct fs_superblock *s_original)
{
	memcpy(&s, s_original, sizeof(struct fs_superblock));
	return 0;
}

void fs_commit_list_init(struct fs_commit_list *list)
{
	struct fs_commit_list_entry *current = list->head, *next = list->head;
	while (current) {
		next = next->next;
		kfree(current);
		current = next;
	}
	list->head = 0;
}

int fs_stage_inode(struct fs_commit_list *list, struct fs_inode *node, enum fs_commit_op_type op)
{
	struct fs_commit_list_entry *entry = kmalloc(sizeof(struct fs_commit_list_entry));

	if (!entry)
		return -1;

	memset(entry, 0, sizeof(struct fs_commit_list_entry));
	entry->data_type = FS_COMMIT_INODE;
	entry->number = node->inode_number;
	entry->op = op;
	entry->data.node = *node;

	fs_commit_list_append(list, entry);

	return 0;
}

int fs_stage_data_block(struct fs_commit_list *list, uint32_t index, uint8_t *buffer, enum fs_commit_op_type op)
{
	struct fs_commit_list_entry *entry = kmalloc(sizeof(struct fs_commit_list_entry));

	if (!entry)
		return -1;

	memset(entry, 0, sizeof(struct fs_commit_list_entry));
	entry->data_type = FS_COMMIT_BLOCK;
	entry->number = index;
	entry->op = op;

	if (op == FS_COMMIT_MODIFY)
		memcpy(entry->data.to_write, buffer, FS_BLOCKSIZE);

	fs_commit_list_append(list, entry);

	return 0;
}

static int fs_try_commit(struct fs_commit_list *list, struct fs_commit_list_entry **last_successful)
{
	struct fs_commit_list_entry *position = list->head;
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
		else if (position->data_type == FS_COMMIT_BLOCK) {
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
			printf("fs: commit failed\n");
			*last_successful = position;
			return ret;
		}
		position = position->next;
	}
	return 0;
}

static int fs_rollback(struct fs_commit_list *list, struct fs_commit_list_entry *last_successful)
{
	struct fs_commit_list_entry *position = last_successful;
	while (position) {
		int ret = 0;
		if (!position->is_completed) {
			position = position->prev;
			continue;
		}
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
		else if (position->data_type == FS_COMMIT_BLOCK) {
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
			printf("fs: rollback failed\n");
			return ret;
		}
		position = position->prev;
	}
	return 0;
}

int fs_commit(struct fs_commit_list *list)
{
	struct fs_commit_list_entry *last_successful;
	int ret = fs_try_commit(list, &last_successful);
	if (ret < 0)
		fs_rollback(list, last_successful);
	return ret;
}
