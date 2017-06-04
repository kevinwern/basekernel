#include "fs_ata.h"
#include "fs.h"

#include "ata.h"
#include "hashtable.h"
#include "string.h"
#define RESERVED_BIT_TABLE_LEN 1024

static struct hash_set *reserved_bits;

int fs_ata_init_reserved()
{
	reserved_bits = hash_set_init(RESERVED_BIT_TABLE_LEN);
	return !!reserved_bits;
}

int fs_ata_read_block(uint32_t index, uint8_t *buffer)
{
	uint32_t num_blocks = FS_BLOCKSIZE/ATA_BLOCKSIZE;
	int ret = ata_read(0, buffer, num_blocks, index);
	return ret;
}

int fs_ata_write_block(uint32_t index, uint8_t *buffer)
{
	uint32_t num_blocks = FS_BLOCKSIZE/ATA_BLOCKSIZE;
	int ret = ata_write(0, buffer, num_blocks, index);
	return ret;
}

int fs_ata_set_bit(uint32_t index, uint32_t begin, uint32_t end)
{
	uint8_t bit_buffer[FS_BLOCKSIZE];
	uint32_t bit_block_index = index / (8 * FS_BLOCKSIZE);
	uint32_t bit_block_offset = index % (8 * FS_BLOCKSIZE);
	uint8_t bit_mask = 1u << (7 - bit_block_offset % 8);
        uint32_t key_for_hash = begin * FS_BLOCKSIZE + index;

	if (hash_set_delete(reserved_bits, key_for_hash) < 0)
		return -1;
	if (fs_ata_read_block(begin + bit_block_index, bit_buffer) < 0)
		return -1;
	if ((bit_mask & bit_buffer[bit_block_offset / 8]) > 0)
		return -1;

	bit_buffer[bit_block_offset / 8] |= bit_mask;
	return fs_ata_write_block(begin + bit_block_index, bit_buffer);
}

int fs_ata_unset_bit(uint32_t index, uint32_t begin, uint32_t end)
{
	uint8_t bit_buffer[FS_BLOCKSIZE];
	uint32_t bit_block_index = index / (8 * FS_BLOCKSIZE);
	uint32_t bit_block_offset = index % (8 * FS_BLOCKSIZE);
	uint8_t bit_mask = 1u << (7 - bit_block_offset % 8);

	if (fs_ata_read_block(begin + bit_block_index, bit_buffer) < 0)
		return -1;
	if ((bit_mask & bit_buffer[bit_block_offset / 8]) == 0)
		return -1;
	bit_buffer[bit_block_offset / 8] ^= bit_mask;
	return fs_ata_write_block(begin + bit_block_index, bit_buffer);
}

int fs_ata_check_bit(uint32_t index, uint32_t begin, uint32_t end, bool *res)
{
	uint8_t bit_buffer[FS_BLOCKSIZE];
	uint32_t bit_block_index = index / (8 * FS_BLOCKSIZE);
	uint32_t bit_block_offset = index % (8 * FS_BLOCKSIZE);
	uint8_t bit_mask = 1u << (7 - bit_block_offset % 8);
        uint32_t key_for_hash = begin * FS_BLOCKSIZE + index;

	*res = hash_set_lookup(reserved_bits, key_for_hash);
	if (*res) {
		return 0;
	}
	if (fs_ata_read_block(begin + bit_block_index, bit_buffer) < 0) {
		return -1;
	}
	*res = (bit_mask & bit_buffer[bit_block_offset / 8]) != 0;
	return 0;
}

static int get_available_bit(uint32_t index, uint32_t *res) {
	uint32_t bit_index;
	uint8_t bit_buffer[FS_BLOCKSIZE];
	fs_ata_read_block(index, bit_buffer);

	for (bit_index = 0; bit_index < sizeof(bit_buffer); bit_index++) {
		if (bit_buffer[bit_index] != 255) {
			uint8_t bit = (1u << 7);
			uint32_t offset;
			for (offset = 0; offset < sizeof(uint8_t) * 8; offset += 1) {
				uint32_t potential_result;
				if (!(bit_buffer[bit_index] & bit)) {
					potential_result = index * FS_BLOCKSIZE + bit_index * sizeof(uint8_t) * 8 + offset;
					if(hash_set_add(reserved_bits, potential_result) == 0) {
						*res = potential_result;
						return 0;
					}
				}
				bit >>= 1;
			}
		}
	}
	return -1;
}

int fs_ata_ffs_range(uint32_t start, uint32_t end, uint32_t *res) {
	uint32_t index;
	int result;

	for (index = start; index < end; index++) {
		result = get_available_bit(index, res);
		if (result == 0) {
			*res -= start * FS_BLOCKSIZE;
			return 0;
		}
	}
	return -1;
}
