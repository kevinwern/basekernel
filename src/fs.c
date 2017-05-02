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

static uint32_t ceiling(double d) {
    return (uint32_t) (d + 1.0);
}

static struct fs_superblock s;
static struct fdtable t;
static uint32_t cwd;

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
	ata_read(0, &buffer, 1, 0);
	memcpy(&s, buffer, sizeof(s));
	if (s.magic == FS_MAGIC) {
		printf("fs: fs already initialized on id 0\n");
		fs_print_superblock(s);
		return 1;
	}
	return 0;
}

static struct fs_inode *fs_create_new_inode(uint32_t inode_number) {

	char buffer[FS_BLOCKSIZE];
	struct fs_inode *node = kmalloc(sizeof(struct fs_inode));
	uint32_t index = inode_number - 1;
	uint32_t inodes_per_block = FS_BLOCKSIZE / sizeof(struct fs_inode);
	uint32_t block = index / inodes_per_block;
	uint32_t offset = (index % inodes_per_block) * sizeof(struct fs_inode);
	char bit_buffer[FS_BLOCKSIZE];
	uint32_t bit_block_index = index / (8 * FS_BLOCKSIZE);
	uint32_t bit_block_offset = index % (8 * FS_BLOCKSIZE);

	ata_read(0, &buffer, 1, s.inode_start + block);
	memcpy(node, buffer + offset, sizeof(struct fs_inode));

	ata_read(0, &bit_buffer, 1, s.inode_bitmap_start + bit_block_index);
	bit_buffer[bit_block_offset / 8] |= (128 >> (bit_block_offset % 8));
	ata_write(0, &bit_buffer, 1, s.inode_bitmap_start + bit_block_index);

	return node;
}

static struct fs_inode *fs_get_inode(uint32_t inode_number) {

	char buffer[FS_BLOCKSIZE];
	struct fs_inode *node = kmalloc(sizeof(struct fs_inode));
	uint32_t index = inode_number - 1;
	uint32_t inodes_per_block = FS_BLOCKSIZE / sizeof(struct fs_inode);
	uint32_t block = index / inodes_per_block;
	uint32_t offset = (index % inodes_per_block) * sizeof(struct fs_inode);

	ata_read(0, &buffer, 1, s.inode_start + block);
	memcpy(node, buffer + offset, sizeof(struct fs_inode));

	return node;
}

static int fs_save_inode(struct fs_inode *node) {

	char buffer[FS_BLOCKSIZE];
	uint32_t index = node->inode_number - 1;
	uint32_t inodes_per_block = FS_BLOCKSIZE / sizeof(struct fs_inode);
	uint32_t block = index / inodes_per_block;
	uint32_t offset = (index % inodes_per_block) * sizeof(struct fs_inode);
	char bit_buffer[FS_BLOCKSIZE];
	uint32_t bit_block_index = index / (8 * FS_BLOCKSIZE);
	uint32_t bit_block_offset = index % (8 * FS_BLOCKSIZE);

	ata_read(0, &buffer, 1, s.inode_start + block);
	memcpy(buffer + offset, node, sizeof(struct fs_inode));
	ata_write(0, &buffer, 1, s.inode_start + block);

	ata_read(0, &bit_buffer, 1, s.inode_bitmap_start + bit_block_index);
	bit_buffer[bit_block_offset / 8] |= (128 >> (bit_block_offset % 8));
	ata_write(0, &bit_buffer, 1, s.inode_bitmap_start + bit_block_index);

	return 0;
}

static uint32_t fs_get_available_bit(char *buffer, uint32_t buffer_size) {
	uint32_t index, offset;
	for (index = 0; index < buffer_size; index++) {
		if (buffer[index] != 255) {
			char bit = (1u << 7);
			for (offset = 0; offset < sizeof(char) * 8; offset++) {
				if (!(buffer[index] & bit))
					return index * sizeof(char) * 8 + offset;
				bit >>= 1;
			}
		}
	}
	return -1;
}

static int fs_write_data_block(uint32_t index, char *buffer) {

	char bit_buffer[FS_BLOCKSIZE];
	uint32_t bit_block_index = index / (8 * FS_BLOCKSIZE);
	uint32_t bit_block_offset = index % (8 * FS_BLOCKSIZE);

	ata_read(0, &bit_buffer, 1, s.block_bitmap_start + bit_block_index);
	bit_buffer[bit_block_offset / 8] |= (128 >> (bit_block_offset % 8));
	ata_write(0, &bit_buffer, 1, s.block_bitmap_start + bit_block_index);

	ata_write(0, buffer, 1, s.free_block_start + index);

	return 0;
}

static int fs_read_blocks(uint32_t index, char *buffer, uint32_t blocks) {
	ata_read(0, buffer, 1, index);
	return 0;
}

static uint32_t fs_ffs_bitmap_range(uint32_t start, uint32_t end) {
	uint32_t index, offset;
	char bit_buffer[FS_BLOCKSIZE];

	for (index = start; index < end; index++) {
		fs_read_blocks(index, bit_buffer, 1);
		offset = fs_get_available_bit(bit_buffer, FS_BLOCKSIZE);
		if (offset >= 0)
			return (index - start) * FS_BLOCKSIZE * 8 + offset;
	}
	return -1;
}

static uint32_t fs_get_available_block() {
	return fs_ffs_bitmap_range(s.block_bitmap_start, s.free_block_start);
}

static uint32_t fs_get_available_inode() {
	return fs_ffs_bitmap_range(s.inode_bitmap_start, s.inode_start) + 1;
}

static uint32_t fs_readdir(struct fs_inode *node, struct fs_dir_record **files) {
	char buffer[FS_BLOCKSIZE];
	uint32_t num_files = node->sz / sizeof(struct fs_dir_record);
	*files = kmalloc(sizeof(struct fs_dir_record) * num_files);

	fs_read_blocks(s.free_block_start + node->direct_addresses[0], buffer, 1);
	uint32_t i;
	for (i = 0; i < num_files; i++) {
		memcpy(&(*files)[i], buffer+sizeof(struct fs_dir_record) * i, sizeof(struct fs_dir_record));
	}

	return num_files;
}

int fs_lsdir() {
	struct fs_inode *node = fs_get_inode(cwd);
	struct fs_dir_record *files;
	uint32_t n = fs_readdir(node, &files);
	uint32_t i;

	for (i = 0; i < n; i++) {
		printf("%s\n", files[i].filename);
	}
	return 0;
}

int fs_init(void) {
	int ret = 0, formatted;
	formatted = fs_check_format();
	if (!formatted) {
		ret = fs_mkfs();
	}
	cwd = 1;
	return ret;
}

int fs_mkfs(void) {

	char wbuffer[FS_BLOCKSIZE];

	uint32_t superblock_num_blocks = ceiling((double) sizeof(struct fs_superblock) / FS_BLOCKSIZE);
	uint32_t available_blocks = FS_SIZE - superblock_num_blocks;
	uint32_t free_blocks = (uint32_t) ((double) (available_blocks)/(1.0 + (double) (sizeof(struct fs_inode) + .125)/FS_BLOCKSIZE + .125/(FS_BLOCKSIZE)));
	uint32_t total_inodes = free_blocks / 8;
	uint32_t total_bits = free_blocks;
	uint32_t inode_sector_size = ceiling((double)(total_inodes * sizeof(struct fs_inode))/FS_BLOCKSIZE);
	uint32_t inode_bit_sector_size = ceiling((double)total_bits/FS_BLOCKSIZE);
	uint32_t bit_sector_size = ceiling((double)total_bits/FS_BLOCKSIZE);

	struct fs_superblock s_new = {
		.magic = FS_MAGIC,
		.blocksize = FS_BLOCKSIZE,

		.inode_bitmap_start = 0,
		.inode_start = 0,
		.block_bitmap_start = 0,
		.free_block_start = 0,

		.num_inodes = 0,
		.num_free_blocks = 0,
	};

	s_new.inode_bitmap_start = superblock_num_blocks;
	s_new.inode_start = s_new.inode_bitmap_start + inode_bit_sector_size;
	s_new.block_bitmap_start = s_new.inode_start + inode_sector_size;
	s_new.free_block_start = s_new.block_bitmap_start + bit_sector_size;
	s_new.num_inodes = total_inodes;
	s_new.num_free_blocks = free_blocks;

	memcpy(wbuffer, &s_new, sizeof(s_new));
	ata_write(0, &wbuffer, 1, 0);
	memcpy(&s, &s_new, sizeof(s));

	memset(wbuffer, 0, sizeof(wbuffer));

	struct fs_dir_record record_self = {
		.filename = ".",
		.inode_number = 1,
	};
	struct fs_dir_record record_parent = {
		.filename = "..",
		.inode_number = 1,
	};

	memcpy(wbuffer, &record_self, sizeof(record_self));
	memcpy(wbuffer + sizeof(record_parent), &record_parent, sizeof(record_parent));

	fs_write_data_block(0, wbuffer);

	uint32_t inode_number = fs_get_available_inode();
	struct fs_inode *new_node = fs_create_new_inode(inode_number);

	new_node->inode_number = 1;
	new_node->is_directory = 1;
	new_node->sz = 2 * sizeof(record_self);
	fs_save_inode(new_node);

	return 0;
}
