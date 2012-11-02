/* 
 * dh.c -- Diffie-Hellman key generation and checking
 * 
 * Copyright (C) 2012  Martin Wolters.
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

#include <Windows.h>

#include "..\include\io.h"
#include "..\include\dh.h"
#include "..\include\tommath.h"

static int mp_add1(mp_int *a, mp_int *b) {
    mp_int one;
    int ret = MP_OKAY;

    if((ret = mp_init(&one)) != MP_OKAY) return ret;

    mp_set(&one, 1);
    ret = mp_add(a, &one, b);

    mp_clear(&one);
    return ret;
}

static int mp_random(mp_int *i, size_t size) {
	unsigned char *c;
	size /= 8;

	if((c = malloc(size)) == NULL)
		return -1;
	fillbuffer(c, size, NULL);
	mp_read_unsigned_bin(i, c, size);
	free(c);

	return MP_OKAY;
}

int mp_gen_key(mp_int *p, mp_int *g, mp_int *a, mp_int *b, size_t size) {
	mp_int small_prime, random, mul, s;
	int test_small = mp_prime_rabin_miller_trials(SMALL_SIZE);
	int test_full = mp_prime_rabin_miller_trials(size);
	int ret;
	size_t randsize = (size - SMALL_SIZE);
	
	/* Generate p */
	if((ret = mp_init_multi(&small_prime, &random, &mul, &s, NULL)) != MP_OKAY)
		return ret;

	printf("Generating q...\n");
	mp_prime_random_ex(&small_prime, test_small, SMALL_SIZE, 0, fillbuffer, NULL);
	
	printf("Generating p...\n");
	do {
		do {
			mp_random(&random, randsize);
		} while(mp_cmp_d(&random, 0) == MP_EQ);
		mp_mul(&small_prime, &random, &mul);
		mp_add1(&mul, p);
		mp_prime_is_prime(p, test_full, &ret);
	} while(!ret);	

	/* Generate g */
	printf("Generating g...\n");
	mp_random(&s, randsize);
	mp_exptmod(&s, &random, p, g);

	/* Generate a */
	printf("Generating a...\n");
	do {
		mp_random(a, size);
	} while(mp_cmp_mag(a, p) != MP_LT);
	
	/* Generate b */
	printf("Generating b...\n");
	do {
		mp_random(b, size);
	} while((mp_cmp_mag(b, p) != MP_LT) && (mp_cmp_mag(a, b) != MP_EQ));

	printf("Done.\n");
	mp_clear_multi(&small_prime, &random, &mul, &s, NULL);	
	return MP_OKAY;
}

int mp_checkkey(mp_int *p, mp_int *g, mp_int *a, mp_int *A, mp_int *b, mp_int *B) {
	mp_int C, kA, kB, kC;

	mp_init_multi(&C, &kA, &kB, &kC, NULL);

	mp_mul(a, b, &C);

	mp_exptmod(B, a, p, &kA);
	mp_exptmod(A, b, p, &kB);
	mp_exptmod(g, &C, p, &kC);
	
	if(mp_cmp_mag(&kA, &kB) != MP_EQ)
		return 0;
	if(mp_cmp_mag(&kB, &kC) != MP_EQ)
		return 0;

	mp_clear_multi(&C, &kA, &kB, &kC, NULL);

	return 1;
}