#ifndef FS_ATA_H
#define FS_ATA_H

#include "kerneltypes.h"
#include "fs.h"

int fs_ata_read_block(uint32_t index, uint8_t *buffer);
int fs_ata_write_block(uint32_t index, uint8_t *buffer);
int fs_ata_set_bit(uint32_t index, uint32_t start, uint32_t end);
int fs_ata_unset_bit(uint32_t index, uint32_t start, uint32_t end);
int fs_ata_check_bit(uint32_t index, uint32_t start, uint32_t end, bool *res);
int fs_ata_ffs_range(uint32_t start, uint32_t end, uint32_t *res);
struct fs_superblock *fs_ata_get_superblock();
int fs_ata_init(bool *already_formatted);

#endif
