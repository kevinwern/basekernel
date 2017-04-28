#include "string.h"
#include "hashtable.h"

uint32_t hash_string(char *string, uint32_t range_min, uint32_t range_max) {
	uint32_t hash = HASHTABLE_PRIME;
	char *curr = string;
	while (*curr) {
		hash = HASHTABLE_PRIME * hash + *curr;
		curr++;
	}
	return (hash % (range_max - range_min)) + range_min;
}
