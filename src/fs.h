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

#include "kerneltypes.h"

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

	uint32_t direct_addresses[10];
	uint32_t direct_addresses_len;
};

struct fs_dir_record {
	char filename[FS_FILENAME_MAXLEN];
	uint32_t inode_number;
};

int fs_init (void);
int fs_mkfs (void);
int fs_lsdir (void);
int fs_mkdir (char *filename);

#endif
