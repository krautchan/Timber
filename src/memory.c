/* 
 * memory.c -- Memory leak detection (with its own memory leaks?)
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

#include <stdlib.h>
#include <string.h>

int n_mallocs = 0;
int n_frees = 0;

typedef struct malloclist_t {
	void *memory;
	char *file;
	int line;
	struct malloclist_t *next;
} malloclist_t;

malloclist_t *mall_list = NULL;

static malloclist_t *make_entry(void *memory, char *file, int line) {
	malloclist_t *out;
	
	if((out = malloc(sizeof(malloclist_t))) == NULL)
		return NULL;	

	out->memory = memory;
	out->line = line;
	out->file = file;	
	out->next = NULL;

	return out;
}

static void free_entry(malloclist_t *entry) {
	free(entry->file);
	free(entry);
}

static void addtolist(malloclist_t *entry) {
	malloclist_t *current = mall_list, *last = NULL;
	if(!current) {
		mall_list = entry;
		return;
	}

	while(current) {		
		last = current;
		current = current->next;
	}
	last->next = entry;
}

static void delfromlist(void *memory) {
	malloclist_t *current = mall_list, *last = NULL;

	while(current) {
		if(current->memory == memory) {
			if(last) {
				last->next = current->next;
			} else {
				mall_list = current->next;
			}
			free_entry(current);
			return;
		}
		last = current;
		current = current->next;
	}

	return;
}

void *mymalloc(size_t size, char *file, int line) {
	void *memory = malloc(size);
	malloclist_t *newentry;
	char *buf;

	if((buf = malloc(strlen(file) + 1))) {
		strcpy(buf, file);		

		if((newentry = make_entry(memory, buf, line))) {
			addtolist(newentry);
		}
	}	

	n_mallocs++;
	return memory;
}

void myfree(void *memory) {
	delfromlist(memory);
	n_frees++;
	free(memory);
}

void showmemstats(FILE *fp) {
	malloclist_t *current = mall_list, *buf;

	if(n_frees < n_mallocs) {
		fprintf(fp, "Showing unfreed memory:\n");
		while(current) {
			fprintf(fp, "%s, %d\n", current->file, current->line);
			buf = current;
			current = current->next;
			free_entry(buf);
		}
	}
	fprintf(fp, "%d malloc()s; %d free()s.\n", n_mallocs, n_frees);
}