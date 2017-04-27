#ifndef FDTABLE_H
#define FDTABLE_H
#define MAX_FD_COUNT (1u<<10)

struct fdtable {
	uint32_t fd_array[MAX_FD_COUNT];
};

#endif
