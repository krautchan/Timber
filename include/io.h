/* 
 * io.h -- io.c header
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

#include "..\include\sha256.h"
#include "..\include\tommath.h"

#ifndef IO_H_
#define IO_H_

unsigned char *xorchar(unsigned char *a, unsigned char *b, size_t size);
int fillbuffer(unsigned char *dst, int len, void *dat);
void mp_print(mp_int *i);
hash_t mp_hash(mp_int *i);
int gentable(char *id, mp_int *in, FILE *fp);
int gensource(mp_int *p, mp_int *g, mp_int *priv, mp_int *pub, mp_int *auth, char *filename);

#endif