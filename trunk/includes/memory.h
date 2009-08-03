#ifndef __MEMORY_H
#define __MEMORY_H

#include <stdlib.h>
#include <stdio.h>

void * allocMem(int size);
void freeMem(void *mem);

#endif
