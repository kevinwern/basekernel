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
    uint32_t i = (uint32_t) d;
    if (d == (double) i)
	    return i;
    return i + 1;
}

static struct fs_superblock s;
static struct fdtable t;
static uint32_t cwd;

static void fs_print_superblock(struct fs_superblock s) {
	printf("fs: magic: %u, blocksize: %u, free_blocks: %u, inode_count: %u, inode_bitmap_start: %u, inode_start: %u, block_bitmap_start: %u, free_block_start: %u \n",
			s.magic,
			s.blocksize,
			s.num_free_blocks,
			s.num_inodes,
			s.inode_bitmap_start,
			s.inode_start,
			s.block_bitmap_start,
			s.free_block_start);
}

static void fs_print_inode(struct fs_inode *n) {
	uint32_t i;
	printf("fs: inode_number: %u, is_directory: %u, sz: %u, direct_addresses_len: %u\n",
			n->inode_number,
			n->is_directory,
			n->sz,
			n->direct_addresses_len);
	for (i = 0; i < n->direct_addresses_len; i++)
		printf("fs: direct_addresses[%u]: %u", i, n->direct_addresses[i]);
}

static void fs_print_dir_record(struct fs_dir_record *d) {
	printf("fs: filename: %s, inode_number: %u\n",
			d->filename,
			d->inode_number);
}

static int fs_check_format(void) {

	uint8_t buffer[FS_BLOCKSIZE];
	ata_read(0, buffer, 1, 0);
	memcpy(&s, buffer, sizeof(s));
	if (s.magic == FS_MAGIC) {
		printf("fs: fs already initialized on id 0\n");
		fs_print_superblock(s);
		return 1;
	}
	return 0;
}

static int set_bit(uint32_t index, uint32_t begin, uint32_t end){
	uint8_t bit_buffer[FS_BLOCKSIZE];
	uint32_t bit_block_index = index / (8 * FS_BLOCKSIZE);
	uint32_t bit_block_offset = index % (8 * FS_BLOCKSIZE);
	uint8_t bit_mask = 1u << (7 - bit_block_offset % 8);

	ata_read(0, bit_buffer, 1, begin + bit_block_index);

	if ((bit_mask & bit_buffer[bit_block_offset / 8]) > 0)
		return -1;

	bit_buffer[bit_block_offset / 8] |= bit_mask;
	ata_write(0, bit_buffer, 1, begin + bit_block_index);

	return 0;
}

static int unset_bit(uint32_t index, uint32_t begin, uint32_t end){
	uint8_t bit_buffer[FS_BLOCKSIZE];
	uint32_t bit_block_index = index / (8 * FS_BLOCKSIZE);
	uint32_t bit_block_offset = index % (8 * FS_BLOCKSIZE);
	uint8_t bit_mask = 1u << (7 - bit_block_offset % 8);

	ata_read(0, bit_buffer, 1, begin + bit_block_index);
	if ((bit_mask & bit_buffer[bit_block_offset / 8]) == 0)
		return -1;

	bit_buffer[bit_block_offset / 8] ^= bit_mask;
	ata_write(0, bit_buffer, 1, begin + bit_block_index);

	return 0;
}

static int check_bit(uint32_t index, uint32_t begin, uint32_t end, bool *res){
	uint8_t bit_buffer[FS_BLOCKSIZE];
	uint32_t bit_block_index = index / (8 * FS_BLOCKSIZE);
	uint32_t bit_block_offset = index % (8 * FS_BLOCKSIZE);
	uint8_t bit_mask = 1u << (7 - bit_block_offset % 8);

	ata_read(0, bit_buffer, 1, begin + bit_block_index);
	*res = (bit_mask & bit_buffer[bit_block_offset / 8]) != 0;

	return 0;
}

static struct fs_inode *fs_create_new_inode(uint32_t inode_number, bool is_directory) {

	struct fs_inode *node;
	uint32_t index = inode_number - 1;

	if (set_bit(index, s.inode_bitmap_start, s.inode_start) < 0)
		return 0;

	node = kmalloc(sizeof(struct fs_inode));
	memset(node, 0, sizeof(struct fs_inode));
	node->inode_number = inode_number;
	node->is_directory = is_directory;

	return node;
}

static struct fs_inode *fs_get_inode(uint32_t inode_number) {

	uint8_t buffer[FS_BLOCKSIZE];
	struct fs_inode *node;
	uint32_t index = inode_number - 1;
	uint32_t inodes_per_block = FS_BLOCKSIZE / sizeof(struct fs_inode);
	uint32_t block = index / inodes_per_block;
	uint32_t offset = (index % inodes_per_block) * sizeof(struct fs_inode);
	bool is_active;

	if (check_bit(index, s.inode_bitmap_start, s.inode_start, &is_active) < 0)
		return 0;
	if (is_active == 0)
		return 0;

	node = kmalloc(sizeof(struct fs_inode));
	ata_read(0, buffer, 1, s.inode_start + block);
	memcpy(node, buffer + offset, sizeof(struct fs_inode));

	return node;
}

static int fs_save_inode(struct fs_inode *node) {

	uint8_t buffer[FS_BLOCKSIZE];
	uint32_t index = node->inode_number - 1;
	uint32_t inodes_per_block = FS_BLOCKSIZE / sizeof(struct fs_inode);
	uint32_t block = index / inodes_per_block;
	uint32_t offset = (index % inodes_per_block) * sizeof(struct fs_inode);
	bool is_active;

	// As of right now, the bit is set via fs_create_new_inode--not ideal,
	// but that means we only check that the node has already been created
	// at some point

	if (check_bit(index, s.inode_bitmap_start, s.inode_start, &is_active) < 0)
		return -1;
	if (is_active == 0)
		return -1;

	ata_read(0, buffer, 1, s.inode_start + block);
	memcpy(buffer + offset, node, sizeof(struct fs_inode));
	ata_write(0, buffer, 1, s.inode_start + block);

	return 0;
}

static int fs_delete_inode(struct fs_inode *node) {

	uint32_t index = node->inode_number - 1;

	// As of right now, the bit is set via fs_create_new_inode--not ideal,
	// but that means we only check that the node has already been created
	// at some point

	if (unset_bit(s.inode_bitmap_start, s.inode_start, index) < 0)
		return -1;

	return 0;
}

static int fs_get_available_bit(uint8_t *buffer, uint32_t buffer_size) {
	int index;
	for (index = 0; index < buffer_size; index++) {
		if (buffer[index] != 255) {
			uint8_t bit = (1u << 7);
			int offset;
			for (offset = 0; offset < sizeof(uint8_t) * 8; offset += 1) {
				if (!(buffer[index] & bit))
					return index * sizeof(uint8_t) * 8 + offset;
				bit >>= 1;
			}
		}
	}
	return -1;
}

static int fs_write_data_block(uint32_t index, uint8_t *buffer) {
	bool is_active;
	if (check_bit(index, s.block_bitmap_start, s.free_block_start, &is_active) < 0) {
		return -1;
	}
	if (is_active == 0) {
		return -1;
	}
	ata_write(0, buffer, 1, s.free_block_start + index);
	return 0;
}

static int fs_read_data_blocks(uint32_t index, uint8_t *buffer, uint32_t blocks) {
	bool is_active;
	if (check_bit(index, s.block_bitmap_start, s.free_block_start, &is_active) < 0) {
		return -1;
	}
	if (is_active == 0) {
		return -1;
	}
	ata_read(0, buffer, 1, s.free_block_start + index);
	return 0;
}

static int fs_read_block_raw(uint32_t index, uint8_t *buffer, uint32_t blocks) {
	ata_read(0, buffer, 1, index);
	return 0;
}

static int fs_ffs_bitmap_range(uint32_t start, uint32_t end, uint32_t *res) {
	uint32_t index;
	int offset;
	uint8_t bit_buffer[FS_BLOCKSIZE];

	for (index = start; index < end; index++) {
		fs_read_block_raw(index, bit_buffer, 1);
		offset = fs_get_available_bit(bit_buffer, FS_BLOCKSIZE);
		if (offset >= 0) {
			*res = (index - start) * FS_BLOCKSIZE * 8 + (uint32_t) offset;
			return 0;
		}
	}
	return -1;
}

static int fs_get_available_block(uint32_t *res) {
	return fs_ffs_bitmap_range(s.block_bitmap_start, s.free_block_start, res);
}

static int fs_get_available_inode(uint32_t *res) {
	int ret = fs_ffs_bitmap_range(s.inode_bitmap_start, s.inode_start, res);
	*res += 1;
	return ret;
}

static uint32_t fs_readdir(struct fs_inode *node, struct fs_dir_record **files) {
	uint8_t buffer[FS_BLOCKSIZE * node->direct_addresses_len];
	uint32_t num_files = node->sz / sizeof(struct fs_dir_record);
	*files = kmalloc(sizeof(struct fs_dir_record) * num_files);

	uint32_t i;
	for (i = 0; i < node->direct_addresses_len; i++) {
		fs_read_data_blocks(node->direct_addresses[i], buffer + i * FS_BLOCKSIZE, 1);
	}

	for (i = 0; i < num_files; i++) {
		memcpy(&(*files)[i], buffer+sizeof(struct fs_dir_record) * i, sizeof(struct fs_dir_record));
	}

	return num_files;
}

static int fs_inode_expand(struct fs_inode *node, uint32_t num_blocks){
	uint32_t new_block[num_blocks], i;
	if (node->direct_addresses_len + num_blocks > FS_INODE_MAXBLOCKS)
		return -1;
	for (i = 0; i < num_blocks; i++){
		if (fs_get_available_block(&(new_block[i])) < 0) {
			printf("exit? 1");
			return -1;
		}
		if (set_bit(new_block[i], s.block_bitmap_start, s.free_block_start) < 0) {
			printf("exit? 2");
			return -1;
		}
	}
	memcpy(node->direct_addresses + node->direct_addresses_len, new_block, sizeof(new_block));
	node->direct_addresses_len += num_blocks;
	return 0;
}

static int fs_writedirs(struct fs_inode *node, struct fs_dir_record *new_files, uint32_t len){
	struct fs_dir_record *files;
	uint32_t n = fs_readdir(node, &files);
	uint8_t *buffer = kmalloc(sizeof(struct fs_dir_record) * (n + len));
	uint32_t i, starting_index = node->sz / FS_BLOCKSIZE, ending_index = (node->sz + len * sizeof(struct fs_dir_record)) / FS_BLOCKSIZE;
	uint32_t num_indices = ceiling((double) node->sz / FS_BLOCKSIZE);
	uint32_t ending_num_indices = ceiling(((double) node->sz + len * sizeof(struct fs_dir_record)) / FS_BLOCKSIZE);
	printf("inode: %u, %u, %u, %u\n", node->inode_number, n + len, node->sz, sizeof(struct fs_dir_record));
	if (((node->sz + len * sizeof(struct fs_dir_record))) % FS_BLOCKSIZE == 0) {
		ending_index--;
	}
	for (i = 0; i < n; i++) {
		memcpy(buffer + sizeof(struct fs_dir_record) * i, &files[i], sizeof(struct fs_dir_record));
	}
	for (i = 0; i < len; i++) {
		memcpy(buffer + sizeof(struct fs_dir_record) * (i+n), &new_files[i], sizeof(struct fs_dir_record));
	}
	if (num_indices < ending_num_indices) {
		fs_inode_expand(node, ending_num_indices - num_indices);
	}
	for (i = starting_index; i <= ending_index; i++) {
		printf("inode: %u %u %u %u\n", i, node->inode_number, node->direct_addresses[i], node->direct_addresses_len);
		fs_write_data_block(node->direct_addresses[i], buffer + FS_BLOCKSIZE * i);
	}
	node->sz += len * sizeof(struct fs_dir_record);
	kfree(files);
	kfree(buffer);
	return 0;
}


static struct fs_dir_record *fs_create_empty_dir(struct fs_inode *node) {
	struct fs_dir_record *links = kmalloc(2 * sizeof(struct fs_dir_record));
	strcpy(links[0].filename, ".");
	links[0].inode_number = node->inode_number;
	strcpy(links[1].filename, "..");
	links[1].inode_number = cwd;
	return links;
}

static struct fs_dir_record *fs_init_record_by_filename(char *filename, struct fs_inode *new_node) {
	uint32_t filename_len = strlen(filename);
	struct fs_dir_record *link;
	if (filename_len > FS_FILENAME_MAXLEN) {
		return 0;
	}

	link = kmalloc(sizeof(struct fs_dir_record));
	strcpy(link->filename,filename);
	link->inode_number = new_node->inode_number;
	return link;
}


int fs_lsdir() {
	struct fs_inode *node = fs_get_inode(cwd);
	fs_print_inode(node);
	struct fs_dir_record *files;
	uint32_t n = fs_readdir(node, &files);
	uint32_t i;

	for (i = 0; i < n; i++) {
		printf("%s\n", files[i].filename);
	}
	kfree(files);
	kfree(node);
	return 0;
}

int fs_mkdir(char *filename) {
	uint32_t new_node_num;
	struct fs_dir_record *new_cwd_record, *new_dir;
	struct fs_inode *new_node, *cwd_node;
	bool is_directory = 1;
	if (fs_get_available_inode(&new_node_num) < 0)
		return -1;
	new_node = fs_create_new_inode(new_node_num, is_directory);
	cwd_node = fs_get_inode(cwd);
	new_dir = fs_create_empty_dir(new_node);
	new_cwd_record = fs_init_record_by_filename(filename, new_node);
	fs_writedirs(new_node, new_dir, 2);
	fs_writedirs(cwd_node, new_cwd_record, 1);

	uint32_t i;
	for (i = 0; i < 2; i++) {
		fs_print_dir_record(&new_dir[i]);
	}
	fs_print_dir_record(new_cwd_record);

	fs_save_inode(new_node);
	fs_save_inode(cwd_node);

	kfree(new_cwd_record);
	kfree(new_dir);
	kfree(new_node);
	kfree(cwd_node);
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

	uint8_t wbuffer[FS_BLOCKSIZE];

	uint32_t superblock_num_blocks = ceiling((double) sizeof(struct fs_superblock) / FS_BLOCKSIZE);
	uint32_t available_blocks = FS_SIZE - superblock_num_blocks;
	uint32_t free_blocks = (uint32_t) ((double) (available_blocks)/(1.0 + (double) (sizeof(struct fs_inode) + .125)/(4.0 * FS_BLOCKSIZE) + .125/(FS_BLOCKSIZE)));
	uint32_t total_inodes = free_blocks / 8;
	uint32_t total_bits = free_blocks;
	uint32_t inode_sector_size = ceiling((double)(total_inodes * sizeof(struct fs_inode))/FS_BLOCKSIZE);
	uint32_t inode_bit_sector_size = ceiling((double)total_bits/FS_BLOCKSIZE);
	uint32_t bit_sector_size = ceiling((double)total_bits/FS_BLOCKSIZE);
	uint32_t inode_number;

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
	ata_write(0, wbuffer, 1, 0);
	memcpy(&s, &s_new, sizeof(s));

	if (fs_get_available_inode(&inode_number) < 0) {
		return -1;
	}

	struct fs_inode *new_node = fs_create_new_inode(inode_number, 1);
	struct fs_dir_record *new_records = fs_create_empty_dir(new_node);
	fs_writedirs(new_node, new_records, 2);
	fs_save_inode(new_node);

	kfree(new_node);

	return 0;
}
