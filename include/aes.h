/* 
 * aes.h -- The AES Encryption Algorithm
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

#ifndef AES_H
#define AES_H

#define FOR_MIX 1
#define INV_MIX 2

#define rotl(i, n) ((i << n) | (i >> (32 - n)))
#define RotByte(i) rotl(i, 8)
#define SubByte(i) ((S[i >> 24] << 24) |\
                    (S[(i >> 16) & 255] << 16) |\
                    (S[(i >> 8) & 255] << 8) |\
                    (S[i & 255] & 255))

#define uchar unsigned char
#define uint unsigned int

#define Nb	4
#define Nk	8
#define Nr	(Nk + 6)

#define BSIZE (Nb * 4)

typedef struct {
	uint *ExpKey;
	uchar *State;
} aes_ctx_t;

void aes_Encrypt(aes_ctx_t Context);
void aes_Decrypt(aes_ctx_t Context);

void aes_UpdateContext(aes_ctx_t *Context, uchar *Msg, uchar *Key);
void aes_InitContext(aes_ctx_t *Context, uchar *Msg, uchar *Key);
void aes_FreeContext(aes_ctx_t Context);
uchar *aes_ContextToChar(aes_ctx_t Context);
#endif
