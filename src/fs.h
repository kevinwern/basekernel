/*
Copyright (C) 2017 The University of Notre Dame
This software is distributed under the GNU General Public License.
See the file LICENSE for details.
*/

#ifndef FS_H
#define FS_H

#define FS_FILENAME_MAXLEN 255
#define FS_MAGIC 0x1209
#define FS_BLOCKSIZE 512
#define FS_SIZE (1u<<20)
#define FS_INODE_MAXBLOCKS 10
#define FS_RESERVED_BITS_COUNT 1024
#define FS_EMPTY_DIR_SIZE 2
#define FS_EMPTY_DIR_SIZE_BYTES FS_EMPTY_DIR_SIZE * sizeof(struct fs_dir_record)
#define FILE_MODE_READ (1u << 0)
#define FILE_MODE_WRITE (1u << 1)

#include "kerneltypes.h"

enum fs_commit_data_type {
	FS_COMMIT_BLOCK,
	FS_COMMIT_INODE,
};

enum fs_commit_op_type {
	FS_COMMIT_CREATE,
	FS_COMMIT_MODIFY,
	FS_COMMIT_DELETE,
};

struct fs_superblock {
	uint32_t magic;
	uint32_t blocksize;

	uint32_t inode_bitmap_start;
	uint32_t inode_start;
	uint32_t block_bitmap_start;
	uint32_t free_block_start;

	uint32_t num_inodes;
	uint32_t num_free_blocks;
};

struct fs_inode {
	uint32_t inode_number;

	uint32_t is_directory;
	uint32_t sz;

	uint32_t direct_addresses[FS_INODE_MAXBLOCKS];
	uint32_t direct_addresses_len;
};

struct fs_commit_list_entry {
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

struct fs_commit_list {
	struct fs_commit_list_entry *head;
};

struct fs_dir_record {
	char filename[FS_FILENAME_MAXLEN];
	uint32_t inode_number;
	bool is_directory;
	int32_t offset_to_next;
};

struct fs_dir_record_list {
	struct fs_dir_record *list;
	struct hash_set *changed;
	uint32_t list_len;
};

int fs_init (void);
int fs_mkfs (void);
int fs_chdir(char *filename);
int fs_lsdir (void);
int fs_mkdir (char *filename);
int fs_rmdir (char *filename);
int fs_open (char *filename, uint8_t mode);
int fs_close (int fd);
int fs_unlink(char *filname);
int fs_write (int fd, uint8_t *buffer, uint32_t n);
int fs_read (int fd, uint8_t *buffer, uint32_t n);

#endif
