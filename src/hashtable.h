#ifndef HASHTABLE_H
#define HASHTABLE_H
#define HASHTABLE_PRIME 31

#include "kerneltypes.h"

uint32_t hash_string(char *string, uint32_t range_min, uint32_t range_max);

#endif
