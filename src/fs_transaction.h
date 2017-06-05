#ifndef FS_TRANSACTION_H
#define FS_TRANSACTION_H
#include "fs.h"

enum fs_commit_data_type
{
	FS_COMMIT_BLOCK,
	FS_COMMIT_INODE,
};

enum fs_commit_op_type
{
	FS_COMMIT_CREATE,
	FS_COMMIT_MODIFY,
	FS_COMMIT_DELETE,
};

struct fs_commit_list_entry
{
	enum fs_commit_op_type op;
	enum fs_commit_data_type data_type;
	bool is_completed;
	uint32_t number;
	union {
		struct fs_inode *node;
		uint8_t *to_revert;
		uint8_t *to_write;
	} data;
	struct fs_commit_list_entry *next;
	struct fs_commit_list_entry *prev;
};

struct fs_commit_list
{
	struct fs_commit_list_entry *head;
};

int fs_transactions_init(struct fs_superblock *s_original);
int fs_commit_list_init(struct fs_commit_list *list);
int fs_stage_inode(struct fs_commit_list *list, struct fs_inode *inode, enum fs_commit_op_type op);
int fs_stage_data_block(struct fs_commit_list *list, uint32_t index, uint8_t *buffer, enum fs_commit_op_type op);
int fs_commit(struct fs_commit_list *list);

#endif
