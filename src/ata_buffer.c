#include "hashtable.h"
#include "list.h"
#include "kmalloc.h"
#include "ata.h"
#include "string.h"
#include "pagetable.h"
#include "memory.h"
#include "device.h"

#define CACHE_SIZE 51

struct ata_cache_entry {
	struct list_node node;
	uint32_t block_no;
	unsigned char *data;
};

struct ata_buffer {
	struct list cache;
	struct hash_set *cache_map;
	int block_size;
};

struct ata_buffer *ata_cache_init(int block_size) {
	struct ata_buffer *ret = kmalloc(sizeof(struct ata_buffer));
	ret->block_size = block_size;
	ret->cache_map = hash_set_init(CACHE_SIZE + 1);
	return ret;
}

int ata_cache_read(struct ata_buffer *buf, int block, void *data) {
	void *read;
	struct ata_cache_entry *cache_entry = 0;
	int exists = hash_set_lookup_info(buf->cache_map, block, &read);
	if (exists) {
		cache_entry = read;
		memcpy(data, cache_entry->data, buf->block_size);
		return 0;
	}
	return -1;
}

int ata_cache_delete (struct ata_buffer *buf, int block){
	void **data = 0;
	struct ata_cache_entry *current_cache_data = 0;
	if (!hash_set_lookup_info(buf->cache_map, block, data)) {
		return -1;
	}
	current_cache_data = *data;
	memory_free_page(current_cache_data->data);
	list_remove((struct list_node*) current_cache_data);
	if (hash_set_delete(buf->cache_map, block) < 0) {
		return -1;
	}
	return 0;
}

int ata_cache_drop_lru(struct ata_buffer *buf) {
	struct ata_cache_entry *current_cache_data = (struct ata_cache_entry *) list_pop_tail(&buf->cache);
	hash_set_delete(buf->cache_map, current_cache_data->block_no);
	return 0;
}

int ata_cache_add(struct ata_buffer *buf, int block, void *data) {
	struct ata_cache_entry *write = 0;
	if (buf->cache_map->num_entries == CACHE_SIZE) ata_cache_drop_lru(buf);
	int exists = hash_set_lookup(buf->cache_map, block);
	if (exists) ata_cache_delete(buf, block);
	write = kmalloc(sizeof(struct ata_cache_entry));
	write->block_no = block;
	write->data = memory_alloc_page(1);
	memcpy(write->data, data, buf->block_size);
	if (hash_set_add(buf->cache_map, block, write) < 0) {
		kfree(write);
		return -1;
	}
	list_push_head(&buf->cache, (struct list_node *) write);
	return 0;
}