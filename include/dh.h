/* 
 * dh.h -- dh.c header
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

#include "..\include\tommath.h"

#ifndef DH_H_
#define DH_H_

#define SMALL_SIZE	320

int mp_gen_key(mp_int *p, mp_int *g, mp_int *a, mp_int *b, size_t size);
int mp_checkkey(mp_int *p, mp_int *g, mp_int *a, mp_int *A, mp_int *b, mp_int *B);

#endif