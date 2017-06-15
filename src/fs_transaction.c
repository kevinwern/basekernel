#include "string.h"
#include "fs_ata.h"
#include "fs.h"
#include "kmalloc.h"

#include "fs_transaction.h"

static struct fs_superblock *super;

static void fs_transaction_append(struct fs_transaction *t, struct fs_transaction_entry *entry)
{
	struct fs_transaction_entry *current = t->head, *prev = 0;
	while (current && !(entry->data_type == current->data_type && entry->number == current->number)) {
		prev = current;
		current = current->next;
	}
	if (prev) {
		prev->next = entry;
		entry->prev = prev;
	}
	else {
		t->head = entry;
	}
	if (current) {
		if (entry->op == FS_TRANSACTION_MODIFY && current->op == FS_TRANSACTION_CREATE)
			entry->op = FS_TRANSACTION_CREATE;
		entry->next = current->next;
		kfree(current);
		entry->next->prev = entry;
	}
}

static int fs_do_delete_inode(struct fs_transaction_entry *entry)
{
	uint32_t inode_number = entry->number;
	uint32_t index = inode_number - 1;

	if (fs_ata_unset_bit(index, super->inode_bitmap_start, super->inode_start) < 0)
		return -1;

	entry->op = FS_TRANSACTION_CREATE;
	entry->is_completed = 1;
	memset(&entry->data.node, 0, sizeof(struct fs_inode));

	return 0;
}

static int fs_do_save_inode(struct fs_transaction_entry *entry)
{
	uint32_t index = entry->number - 1;
	uint32_t inodes_per_block = FS_BLOCKSIZE / sizeof(struct fs_inode);
	uint32_t block = index / inodes_per_block;
	uint32_t offset = index % inodes_per_block;
	struct fs_inode temp;
	struct fs_inode current_nodes[inodes_per_block];

	if (entry->op == FS_TRANSACTION_CREATE) {
		if (fs_ata_set_bit(index, super->inode_bitmap_start, super->inode_start) < 0) {
			return -1;
		}
		entry->op = FS_TRANSACTION_DELETE;
		entry->is_completed = 1;
	}

	if (entry->data.node.inode_number) {
		if (fs_ata_read_block(super->inode_start + block, current_nodes) < 0)
			return -1;
		memcpy(&temp, current_nodes + offset, sizeof(struct fs_inode));
		memcpy(current_nodes + offset, &entry->data.node, sizeof(struct fs_inode));
		if (fs_ata_write_block(super->inode_start + block, current_nodes) < 0)
			return -1;
		entry->data.node = temp;
		entry->is_completed = 1;
	}

	return 0;
}

static int fs_do_delete_data(struct fs_transaction_entry *entry)
{
	uint32_t index = entry->number;

	if (fs_ata_unset_bit(index, super->block_bitmap_start, super->free_block_start) < 0) {
		return -1;
	}

	entry->op = FS_TRANSACTION_CREATE;
	entry->is_completed = 1;
	return 0;
}

static int fs_do_save_data(struct fs_transaction_entry *entry)
{
	uint32_t index = entry->number;
	uint8_t temp[FS_BLOCKSIZE];
	bool is_valid;


	if (entry->op == FS_TRANSACTION_CREATE) {
		if (fs_ata_set_bit(index, super->block_bitmap_start, super->free_block_start) < 0) {
			return -1;
		}
		entry->op = FS_TRANSACTION_DELETE;
		entry->is_completed = 1;
	}
	else if (fs_ata_check_bit(index, super->block_bitmap_start, super->free_block_start, &is_valid) < 0 || !is_valid)
		return -1;


	memcpy(temp, entry->data.to_write, sizeof(temp));
	if (fs_ata_write_block(super->free_block_start + index, temp) < 0)
		return -1;
	entry->is_completed = 1;

	return 0;
}

int fs_transactions_init(struct fs_superblock *s_original)
{
	super = s_original;
	return 0;
}

void fs_transaction_init(struct fs_transaction *t)
{
	struct fs_transaction_entry *current = t->head, *next = t->head;
	while (current) {
		next = next->next;
		kfree(current);
		current = next;
	}
	t->head = 0;
}

int fs_transaction_stage_inode(struct fs_transaction *t, struct fs_inode *node, enum fs_transaction_op_type op)
{
	struct fs_transaction_entry *entry = kmalloc(sizeof(struct fs_transaction_entry));

	if (!entry)
		return -1;

	memset(entry, 0, sizeof(struct fs_transaction_entry));
	entry->data_type = FS_TRANSACTION_INODE;
	entry->number = node->inode_number;
	entry->op = op;
	entry->data.node = *node;

	fs_transaction_append(t, entry);

	return 0;
}

int fs_transaction_stage_data(struct fs_transaction *t, uint32_t index, uint8_t *buffer, enum fs_transaction_op_type op)
{
	struct fs_transaction_entry *entry = kmalloc(sizeof(struct fs_transaction_entry));

	if (!entry)
		return -1;

	memset(entry, 0, sizeof(struct fs_transaction_entry));
	entry->data_type = FS_TRANSACTION_BLOCK;
	entry->number = index;
	entry->op = op;

	if (op == FS_TRANSACTION_MODIFY)
		memcpy(entry->data.to_write, buffer, FS_BLOCKSIZE);

	fs_transaction_append(t, entry);

	return 0;
}

static int fs_try_commit_entry(struct fs_transaction_entry *entry)
{
	int ret = -1;
	if (entry->data_type == FS_TRANSACTION_INODE) {
		switch (entry->op) {
			case FS_TRANSACTION_CREATE:
			case FS_TRANSACTION_MODIFY:
				ret = fs_do_save_inode(entry);
				break;
			case FS_TRANSACTION_DELETE:
				ret = fs_do_delete_inode(entry);
				break;
		}
	}
	else if (entry->data_type == FS_TRANSACTION_BLOCK) {
		switch (entry->op) {
			case FS_TRANSACTION_CREATE:
			case FS_TRANSACTION_MODIFY:
				ret = fs_do_save_data(entry);
				break;
			case FS_TRANSACTION_DELETE:
				ret = fs_do_delete_data(entry);
				break;
		}
	}
	return ret;
}

static int fs_try_commit(struct fs_transaction *t, struct fs_transaction_entry **last_successful)
{
	struct fs_transaction_entry *position = t->head;
	while (position) {
		int ret = fs_try_commit_entry(position);
		if (ret < 0) {
			printf("fs: commit failed\n");
			*last_successful = position;
			return ret;
		}
		position = position->next;
	}
	return 0;
}

static int fs_rollback(struct fs_transaction *t, struct fs_transaction_entry *last_successful)
{
	struct fs_transaction_entry *position = last_successful;
	while (position) {
		int ret;
		if (!position->is_completed) {
			position = position->prev;
			continue;
		}
		ret = fs_try_commit_entry(position);
		if (ret < 0) {
			printf("fs: rollback failed\n");
			return ret;
		}
		position = position->prev;
	}
	return 0;
}

int fs_transaction_commit(struct fs_transaction *t)
{
	struct fs_transaction_entry *last_successful;
	int ret = fs_try_commit(t, &last_successful);
	if (ret < 0)
		fs_rollback(t, last_successful);
	return ret;
}
