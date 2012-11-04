/* 
 * keygen.c -- Generate a key for the logger client and server
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
#include <Windows.h>

#include "..\include\io.h"
#include "..\include\dh.h"
#include "..\include\sha256.h"
#include "..\include\tommath.h"
#include "..\include\memory.h"

#define SIZE_MIN	512

int main(int argc, char **argv) {
	int ret = EXIT_FAILURE;
	size_t size;
	mp_int p, g, a, A, b, B, c;
	hash_t key;

	if(argc == 1)
		size = SIZE_MIN;
	else {
		size = atoi(argv[1]);
		if(size < SIZE_MIN)
			size = SIZE_MIN;
		if(size % 8) {
			size /= 8;
			size *= 8;
			size += 8;
		}
	}	

	printf("Key size = %d\n", size);
	if(mp_init_multi(&p, &g, &a, &A, &b, &B, &c, NULL) != MP_OKAY)
		return EXIT_FAILURE;

	if(mp_gen_key(&p, &g, &a, &b, size) != MP_OKAY)
		goto clear;
	
	mp_exptmod(&g, &a, &p, &A);
	mp_exptmod(&g, &b, &p, &B);

	printf("Checking keypair... ");
	if(!mp_checkkey(&p, &g, &a, &A, &b, &B)) {
		printf("Failed.\n");
		goto clear;
	}
	printf("OK.\n");

	gensource(&p, &g, &a, &A, &B, "client_key.h");
	gensource(&p, &g, &b, &B, &A, "server_key.h");

	mp_exptmod(&A, &b, &p, &c);
	key = mp_hash(&c);

	printf("Agreed Key:\n%08x %08x %08x %08x ", key.h0, key.h1, key.h2, key.h3);
	printf("%08x %08x %08x %08x\n", key.h4, key.h5, key.h6, key.h7);
	free(key.string);

	mp_exptmod(&B, &a, &p, &c);
	key = mp_hash(&c);

	printf("Check:\n%08x %08x %08x %08x ", key.h0, key.h1, key.h2, key.h3);
	printf("%08x %08x %08x %08x\n", key.h4, key.h5, key.h6, key.h7);
	free(key.string);

	ret = EXIT_SUCCESS;
clear:
	mp_clear_multi(&p, &g, &a, &b, &A, &B, &c, NULL);
	showmemstats(stdout);

	return ret;
}