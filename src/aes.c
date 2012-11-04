/* 
 * aes.c -- The AES Encryption Algorithm
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

#include "..\include\aes.h"
#include "..\include\tables.h"
#include "..\include\memory.h"

static void SubBytes(uchar *State) {
	int i;
	for(i = 0; i < BSIZE; i++)
		State[i] = S[State[i]];
}

static void inv_SubBytes(uchar *State) {
	int i;
	for(i = 0; i < BSIZE; i++)
		State[i] = inv_S[State[i]];
}

static void ShiftRows(uchar *State) {
	uchar temp;

	temp = State[Nb];
	State[Nb] = State[Nb + 1];
	State[Nb + 1] = State[Nb + 2];
	State[Nb + 2] = State[Nb + 3];
	State[Nb + 3] = temp;

	temp = State[2 * Nb];
	State[2 * Nb] = State[2 * Nb + 2];
	State[2 * Nb + 2] = temp;
	temp = State[2 * Nb + 1];
	State[2 * Nb + 1] = State[2 * Nb + 3];
	State[2 * Nb + 3] = temp;

	temp = State[3 * Nb + 3];
	State[3 * Nb + 3] = State[3 * Nb + 2];
	State[3 * Nb + 2] = State[3 * Nb + 1];
	State[3 * Nb + 1] = State[3 * Nb];
	State[3 * Nb] = temp;
}

static void inv_ShiftRows(uchar *State) {
	uchar temp;

	temp = State[Nb + 3];
	State[Nb + 3] = State[Nb + 2];
	State[Nb + 2] = State[Nb + 1];
	State[Nb + 1] = State[Nb];
	State[Nb] = temp;

	temp = State[2 * Nb];
	State[2 * Nb] = State[2 * Nb + 2];
	State[2 * Nb + 2] = temp;
	temp = State[2 * Nb + 1];
	State[2 * Nb + 1] = State[2 * Nb + 3];
	State[2 * Nb + 3] = temp;

	temp = State[3 * Nb];
	State[3 * Nb] = State[3 * Nb + 1];
	State[3 * Nb + 1] = State[3 * Nb + 2];
	State[3 * Nb + 2] = State[3 * Nb + 3];
	State[3 * Nb + 3] = temp;
}

/* 
 * The following functions are taken from 
 * http://www.codeplanet.eu/tutorials/cpp/51-advanced-encryption-standard.html
 */

static uchar MulGF(uchar a, uchar b) {
	uchar out = 0, hi, i;

	for(i = 0; i < 8; i++) {
		if(b & 1)
			out ^= a;
		hi = a & 0x80;
		a <<= 1;
		if(hi)
			a ^= 0x1b;
		b >>= 1;
	}

	return out;
}

static void MixColumn(uchar *Column) {
	int i;
	uchar cpy[4];

	for(i = 0; i < 4; i ++)
		cpy[i] = Column[i];

	Column[0] = MulGF(cpy[0], 2) ^
				MulGF(cpy[1], 3) ^
				MulGF(cpy[2], 1) ^
				MulGF(cpy[3], 1);

	Column[1] = MulGF(cpy[0], 1) ^
				MulGF(cpy[1], 2) ^
				MulGF(cpy[2], 3) ^
				MulGF(cpy[3], 1);

	Column[2] = MulGF(cpy[0], 1) ^
				MulGF(cpy[1], 1) ^
				MulGF(cpy[2], 2) ^
				MulGF(cpy[3], 3);

	Column[3] = MulGF(cpy[0], 3) ^
				MulGF(cpy[1], 1) ^
				MulGF(cpy[2], 1) ^
				MulGF(cpy[3], 2);
}

static void inv_MixColumn(uchar *Column) {
	int i;
	uchar cpy[4];

	for(i = 0; i < 4; i ++)
		cpy[i] = Column[i];

	Column[0] = MulGF(cpy[0], 0xe) ^
				MulGF(cpy[1], 0xb) ^
				MulGF(cpy[2], 0xd) ^
				MulGF(cpy[3], 0x9);

	Column[1] = MulGF(cpy[0], 0x9) ^
				MulGF(cpy[1], 0xe) ^
				MulGF(cpy[2], 0xb) ^
				MulGF(cpy[3], 0xd);

	Column[2] = MulGF(cpy[0], 0xd) ^
				MulGF(cpy[1], 0x9) ^
				MulGF(cpy[2], 0xe) ^
				MulGF(cpy[3], 0xb);

	Column[3] = MulGF(cpy[0], 0xb) ^
				MulGF(cpy[1], 0xd) ^
				MulGF(cpy[2], 0x9) ^
				MulGF(cpy[3], 0xe);
}

static void MixColumns(uchar *State, int mode) {
	int i, j;
	uchar Column[4];

	for(i = 0; i < Nb; i++) {
		for(j = 0; j < 4; j++)
			Column[j] = State[4 * j + i];

		if(mode == FOR_MIX)
			MixColumn(Column);
		else
			inv_MixColumn(Column);

		for(j = 0; j < 4; j++)
			State[4 * j + i] = Column[j];
	}
}

static void AddRoundKey(uchar *State, uint *ExpKey, int Round) {
	int i;
	for(i = 0; i < Nb; i++) {
		State[i] ^= ExpKey[Round * Nb + i] >> 24;
		State[Nb + i] ^= ((ExpKey[Round * Nb + i] >> 16) & 255);
		State[2 * Nb + i] ^= ((ExpKey[Round * Nb + i] >> 8) & 255);
		State[3 * Nb + i] ^= (ExpKey[Round * Nb + i] & 255);
	}
}

static uint *KeyExpansion(uint *Key) {
	int i;
	uint temp, *W;

	if((W = malloc(Nb * (Nr + 1) * sizeof(uint))) == NULL)
		return NULL;

	for(i = 0; i < Nk; i++)
		W[i] = Key[i];

	for(i = Nk; i < Nb * (Nr + 1); i++) {
		temp = W[i - 1];
		if(i % Nk == 0) {
			temp = SubByte(RotByte(temp)) ^ (Rcon[i / Nk] << 24);
		}
#if Nk > 6
		else if(i % Nk == 4)
			temp = SubByte(temp);
#endif
		W[i] = W[i - Nk] ^ temp;
	}

	return W;
}

static uchar *MsgToState(uchar *Msg) {
    uchar *State;
    int i;

    if((State = malloc(BSIZE)) == NULL)
        return NULL;

    for(i = 0; i < Nb; i++) {
        State[i] = Msg[i * Nb];
        State[Nb + i] = Msg[i * Nb + 1];
        State[2 * Nb + i] = Msg[i * Nb + 2];
        State[3 * Nb + i] = Msg[i * Nb + 3];
    }

    return State;
}

void aes_Encrypt(aes_ctx_t Context) {
	int i;
	uint *ExpKey = Context.ExpKey;
	uchar *State = Context.State;

	AddRoundKey(State, ExpKey, 0);
	for(i = 1; i < Nr; i++) {
		SubBytes(State);
		ShiftRows(State);
		MixColumns(State, FOR_MIX);
		AddRoundKey(State, ExpKey, i);
	}
	SubBytes(State);
	ShiftRows(State);
	AddRoundKey(State, ExpKey, Nr);
}

void aes_Decrypt(aes_ctx_t Context) {
	int i;
	uint *ExpKey = Context.ExpKey;
	uchar *State = Context.State;

	AddRoundKey(State, ExpKey, Nr);
	inv_ShiftRows(State);
	inv_SubBytes(State);
	for(i = Nr - 1; i > 0; i--) {
		AddRoundKey(State, ExpKey, i);
		MixColumns(State, INV_MIX);
		inv_ShiftRows(State);
		inv_SubBytes(State);
	}
	AddRoundKey(State, ExpKey, 0);
}

void aes_UpdateContext(aes_ctx_t *Context, uchar *Msg, uchar *Key) {
	uint IntKey[Nk];
	int i;

	if(Key) {
		free(Context->ExpKey);
		for(i = 0; i < Nk; i++)
			IntKey[i] = Key[i * 4] << 24 |
						Key[i * 4 + 1] << 16 |
						Key[i * 4 + 2] << 8 |
						Key[i * 4 + 3];
		Context->ExpKey = KeyExpansion(IntKey);
	}	
	
	if(Msg) {
		free(Context->State);
		Context->State = MsgToState(Msg);
	}
}

void aes_InitContext(aes_ctx_t *Context, uchar *Msg, uchar *Key) {
	uint IntKey[Nk];
	int i;
	
	for(i = 0; i < Nk; i++)
		IntKey[i] = Key[i * 4] << 24 |
					Key[i * 4 + 1] << 16 |
					Key[i * 4 + 2] << 8 |
					Key[i * 4 + 3];
	Context->ExpKey = KeyExpansion(IntKey);

	Context->State = MsgToState(Msg);
}

void aes_FreeContext(aes_ctx_t Context) {
	free(Context.ExpKey);
	free(Context.State);
}

/* TODO!! */

uchar *aes_ContextToChar(aes_ctx_t Context) {
	uchar *out = malloc(BSIZE);
	int i, j;

	if(out == NULL)
		return NULL;

	for(i = 0; i < 4; i++) {
		for(j = 0; j < Nb; j++) {
			out[i * Nb + j] = Context.State[j * Nb + i];
		}
	}
	return out;
}
