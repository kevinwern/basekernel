/*
Copyright (C) 2017 The University of Notre Dame
This software is distributed under the GNU General Public License.
See the file LICENSE for details.
*/

#include "kerneltypes.h"
#include "ata.h"

#include "fs.h"
#include "string.h"

static uint32_t ceiling(double d) {
    return (uint32_t) (d + 1.0);
}

static void fs_print_superblock(struct fs_superblock s) {
	printf("fs: magic: %u, blocksize: %u, free_blocks: %u, inode_count: %u, inode_start: %u, block_bitmap_start: %u, free_block_start: %u \n",
			s.magic,
			s.blocksize,
			s.num_free_blocks,
			s.num_inodes,
			s.inode_start,
			s.block_bitmap_start,
			s.free_block_start);
}

static int fs_check_format(void) {

	char buffer[FS_BLOCKSIZE];
	struct fs_superblock s_curr;
	ata_read(0, &buffer, 1, 0);
	memcpy(&s_curr, buffer, sizeof(s_curr));
	if (s_curr.magic == FS_MAGIC) {
		printf("fs: fs already initialized on id 0\n");
		fs_print_superblock(s_curr);
		return 1;
	}
	return 0;
}

int fs_init(void) {
	int ret = 0, formatted;
	formatted = fs_check_format();
	if (!formatted) {
		ret = fs_mkfs();
	}
	return ret;
}

int fs_mkfs(void) {

	char wbuffer[FS_BLOCKSIZE];

	uint32_t fs_superblock_num_blocks = ceiling((double) sizeof(struct fs_superblock) / FS_BLOCKSIZE);
	uint32_t available_blocks = FS_SIZE - fs_superblock_num_blocks;
	uint32_t free_blocks = (uint32_t) ((double) (available_blocks)/(1.0 + (double) sizeof(struct fs_inode)/FS_BLOCKSIZE + (double) sizeof(char)/FS_BLOCKSIZE));
	uint32_t total_inodes = free_blocks / 8;
	uint32_t total_bits = free_blocks;
	uint32_t inode_sector_size = ceiling((double)(total_inodes * sizeof(struct fs_inode))/FS_BLOCKSIZE);
	uint32_t bit_sector_size = ceiling((double)total_bits/FS_BLOCKSIZE);

	struct fs_superblock s = {
		.magic = FS_MAGIC,
		.blocksize = FS_BLOCKSIZE,

		.inode_start = 0,
		.block_bitmap_start = 0,
		.free_block_start = 0,

		.num_inodes = 0,
		.num_free_blocks = 0,
	};

	s.inode_start = fs_superblock_num_blocks;
	s.block_bitmap_start = s.inode_start + inode_sector_size;
	s.free_block_start = s.block_bitmap_start + bit_sector_size;
	s.num_inodes = total_inodes;
	s.num_free_blocks = free_blocks;

	memcpy(wbuffer, &s, sizeof(s));
	ata_write(0, &wbuffer, 1, 0); 

	return 0;
}
