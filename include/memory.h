/* 
 * memory.h -- memory.c header
 * 
 * Copyright (C) 2012  Martin Wolters
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to 
 * the Free Software Foundation, Inc.
 * 51 Franklin Street, Fifth Floor
 * Boston, MA  02110-1301, USA
 * 
 */

#include <stdio.h>

#ifndef UTIL_H_
#define UTIL_H_

#define malloc(size) mymalloc((size), __FILE__, __LINE__)
#define free(memory) myfree(memory)

int n_mallocs, n_frees;

void *mymalloc(size_t size, char *file, int line);
void myfree(void *memory);
void showmemstats(FILE *fp);

#endif