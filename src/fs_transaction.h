#ifndef FS_TRANSACTION_H
#define FS_TRANSACTION_H
#include "fs.h"

enum fs_transaction_data_type
{
	FS_TRANSACTION_BLOCK,
	FS_TRANSACTION_INODE,
};

enum fs_transaction_op_type
{
	FS_TRANSACTION_CREATE,
	FS_TRANSACTION_MODIFY,
	FS_TRANSACTION_DELETE,
};

struct fs_transaction_entry
{
	enum fs_transaction_op_type op;
	enum fs_transaction_data_type data_type;
	bool is_completed;
	uint32_t number;
	union {
		struct fs_inode node;
		uint8_t to_write[FS_BLOCKSIZE];
		uint8_t to_revert[FS_BLOCKSIZE];
	} data;
	struct fs_transaction_entry *next;
	struct fs_transaction_entry *prev;
};

struct fs_transaction
{
	struct fs_transaction_entry *head;
};

int fs_transactions_init(struct fs_superblock *s_original);
void fs_transaction_init(struct fs_transaction *t);
int fs_transaction_stage_inode(struct fs_transaction *t, struct fs_inode *inode, enum fs_transaction_op_type op);
int fs_transaction_stage_data(struct fs_transaction *t, uint32_t index, uint8_t *buffer, enum fs_transaction_op_type op);
int fs_transaction_commit(struct fs_transaction *t);

#endif
