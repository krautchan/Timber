/* 
 * net.c -- netcode
 * 
 * Copyright (C) 2012  Martin Wolters et al.
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

#include <WinSock2.h>
#include <Windows.h>
#include <stdio.h>

#include "..\include\aes.h"
#include "..\include\io.h"
#include "..\include\logger.h"
#include "..\include\net.h"
#include "..\include\sha256.h"
#include "..\include\tommath.h"

#ifdef LOG_SERVER
#include "server_key.h"
#elif defined LOG_CLIENT
#include "client_key.h"
#else
#error Network role unknown.
#endif

static int checknonce(unsigned char *data) {
	int i;

	for(i = 0; i < Nb * 2; i++)
		if(data[i] != conn.nonce[i])
			return 0;
		
	return 1;
}

static int CheckHash(char *c, size_t size) {
	hash_t hash = sha256(c, size);
	if ((hash.h0 != dh_key_authed[0]) ||
		(hash.h1 != dh_key_authed[1]) ||
		(hash.h2 != dh_key_authed[2]) ||
		(hash.h3 != dh_key_authed[3]) ||
		(hash.h4 != dh_key_authed[4]) ||
		(hash.h5 != dh_key_authed[5]) ||
		(hash.h6 != dh_key_authed[6]) ||
		(hash.h7 != dh_key_authed[7])) {
			return 0;
	}
	return 1;
}

static void EstablishSharedSecret(void) {
	mp_int p, a, b, k;
	int size;
	unsigned char *key;
	hash_t hash;

	mp_init_multi(&p, &a, &b, &k, NULL);

	mp_read_unsigned_bin(&p, dh_key_p, sizeof(dh_key_p));
	mp_read_unsigned_bin(&a, dh_key_priv, sizeof(dh_key_priv));
	mp_read_unsigned_bin(&b, conn.dh_remote_key, conn.dh_remote_key_size);

	mp_exptmod(&b, &a, &p, &k);
	size = mp_unsigned_bin_size(&k);
	key = malloc(size);
	mp_to_unsigned_bin(&k, key);
	
	hash = sha256(key, size);
	conn.dh_shared_key = malloc(32);
	memcpy(conn.dh_shared_key, hash.string, 32);

	mp_clear_multi(&p, &a, &b, &k, NULL);
}

int StartWinsock(void) {
	WSADATA wsa;
	return WSAStartup(MAKEWORD(2,0), &wsa);
}

unsigned char *crypt_recv(SOCKET s) {
	int blocks, i;
	unsigned char IV[Nb * 4], ct[Nb * 4], *pt, *out;
	aes_ctx_t context;

	if((recv(s, (char*)&blocks, sizeof(blocks), 0)) != sizeof(blocks))
		return NULL;

	if(blocks < 1)
		return NULL;

	if((out = malloc((blocks - 1) * Nb * 4)) == NULL)
		return NULL;

//	memset(out, 0, (blocks - 1) * Nb * 4);
	recv(s, IV, Nb * 4, 0);

	for(i = 1; i < blocks; i++) {
		if(recv(s, ct, Nb * 4, 0) == 0) {			
			free(out);
			return NULL;
		}

		aes_InitContext(&context, ct, conn.dh_shared_key);
		aes_Decrypt(context);
		pt = aes_ContextToChar(context);
		pt = xorchar(pt, IV, Nb * 4);

		memcpy(out + (i - 1) * Nb * 4, pt, Nb * 4);
		free(pt);
		memcpy(IV, ct, Nb * 4);
	}

	return out;
}

int crypt_send(SOCKET s, unsigned char *data, size_t size) {
	unsigned char IV[Nb * 4], lastblock[4 * Nb], *ct, *pt;
	int blocks;
	aes_ctx_t context;

	blocks = 1;
	blocks += size / (Nb * 4);
	blocks += (size % (Nb * 4))?1:0;

	send(s, (char*)&blocks, sizeof(blocks), 0);
	fillbuffer(IV, Nb * 4, NULL);
	send(s, (char*)IV, Nb * 4, 0);
		
	while(size > (Nb * 4)) {
		pt = xorchar(data, IV, Nb * 4);
		aes_InitContext(&context, pt, conn.dh_shared_key);
		free(pt);
		aes_Encrypt(context);
		ct = aes_ContextToChar(context);

		send(s, ct, Nb * 4, 0);
		memcpy(IV, ct, Nb * 4);

		aes_FreeContext(context);
		free(ct);
		
		size -= Nb * 4;
		data += Nb * 4;
	}

	if(size) {
		memset(lastblock, 0, Nb * 4);
		memcpy(lastblock, data, size);

		pt = xorchar(lastblock, IV, Nb * 4);
		aes_InitContext(&context, pt, conn.dh_shared_key);
		free(pt);
		aes_Encrypt(context);
		ct = aes_ContextToChar(context);
		aes_FreeContext(context);
		
		send(s, ct, Nb * 4, 0);
		free(ct);
	}

	return blocks;
}

int recv_msg(SOCKET s) {
	unsigned char *data;
	int msg;
	
	if((data = crypt_recv(s)) == NULL) {
		return MSG_ERR;
	}

	if(!checknonce(data)) {
		free(data);
		return MSG_ERR;
	}	
	memcpy(&msg, data + Nb * 4 - sizeof(msg), sizeof(msg));

	free(data);
	return msg;
}

int send_msg(SOCKET s, int msg) {
	unsigned char data[Nb * 4];

	/* compose message */
	memset(data, 0, Nb * 4);
	memcpy(data, conn.nonce, Nb * 2);
	memcpy(data + Nb * 4 - sizeof(msg), &msg, sizeof(msg));

	crypt_send(s, data, Nb * 4);

	return 1;
}

int ClientHandshake(SOCKET s) {
	int magic, version, rep;
	unsigned char encnonce[Nb * 4];
	size_t size;
	hash_t hash;
	aes_ctx_t context;

	printf("Starting handshake...\nChecking Magic... ");
	if(recv(s, (char*)&magic, sizeof(magic), 0) != sizeof(magic)) {
		printf("ERROR: Short read.\n");
		return 0;
	}

	if(magic != PROTO_MAGIC) {
		printf("ERROR: Mismatch.\n");
		return 0;
	}

	printf("OK\nChecking protocol version... ");
	if(recv(s, (char*)&version, sizeof(version), 0) != sizeof(version)) {
		printf("ERROR: Short read.\n");
		return 0;
	}

	if(version != PROTO_VER) {
		printf("ERROR: Mismatch.\n");
		return 0;
	}

	printf("OK.\nSending Magic... ");	
	if(send(s, (char*)&magic, sizeof(magic), 0) != sizeof(magic)) {
		printf("ERROR: Short write.\n");
		return 0;
	}

	printf("OK.\nSending protocol version... ");
	if(send(s, (char*)&version, sizeof(version), 0) != sizeof(version)) {
		printf("ERROR: Short write.\n");
		return 0;
	}
	
	if(recv(s, (char*)&rep, sizeof(rep), 0) != sizeof(rep)) {
		printf("ERROR: Short read.\n");
		return 0;
	}

	if(rep != MSG_ACK) {
		printf("ERROR: Server declined.\n");
		return 0;
	}

	printf("OK.\nReceiving Server's public key... ");
	if(recv(s, (char*)&conn.dh_remote_key_size, sizeof(conn.dh_remote_key_size), 0) != sizeof(conn.dh_remote_key_size)) {
		printf("ERROR: Short read.\n");
		return 0;
	}

	printf("(%d bits) ", conn.dh_remote_key_size * 8);
	if((conn.dh_remote_key = malloc(conn.dh_remote_key_size)) == NULL) {
		printf("ERROR: malloc() failed.\n");
		return 0;
	}

	if(recv(s, conn.dh_remote_key, conn.dh_remote_key_size, 0) != conn.dh_remote_key_size) {
		printf("ERROR: Short read.\n");
		return 0;
	}

	printf("OK.\nAuthenticating public key... ");
	hash = sha256(conn.dh_remote_key, conn.dh_remote_key_size);
	
	if (!CheckHash(conn.dh_remote_key, conn.dh_remote_key_size)) {
		printf("Failed.\n");
		return 0;
	}
	printf("OK.\nSending my public key... ");

	size = sizeof(dh_key_pub);
	printf("(%d bits) ", size * 8);

	if(send(s, (char*)&size, sizeof(size), 0) != sizeof(size)) {
		printf("ERROR: Short write.\n");
		return 0;
	}
	if(send(s, dh_key_pub, size, 0) != size) {
		printf("ERROR: Short write.\n");
		return 0;
	}

	if(recv(s, (char*)&rep, sizeof(rep), 0) != sizeof(rep)) {
		printf("ERROR: Short read.\n");
		return 0;
	}

	if(rep != MSG_ACK) {
		printf("ERROR: Server declined.\n");
		return 0;
	}
	printf("OK.\n");

	EstablishSharedSecret();
	
	printf("Shared secret established.\nReceiving nonce... ");
	recv(s, encnonce, Nb * 4, 0);
	
	aes_InitContext(&context, encnonce, conn.dh_shared_key);
	aes_Decrypt(context);
	conn.nonce = aes_ContextToChar(context);
	aes_FreeContext(context);

	printf("Ok.\nHandshake complete.\n\n");
	printf("PING... ");

	send_msg(s, MSG_PING);
	if(recv_msg(s) == MSG_PONG) {
		printf("PONG!\n\n");
		return 1;
	}
	
	printf(":(\n");
	return 0;
}

int ServerHandshake(SOCKET s) {
	size_t size;
	int magic = PROTO_MAGIC;
	int version = PROTO_VER;
	int ack = MSG_ACK, nack = MSG_NACK;
	aes_ctx_t context;
	unsigned char *encnonce;

	/* Header */
	send(s, (char*)&magic, sizeof(magic), 0);
	send(s, (char*)&version, sizeof(version), 0);
	
	if(recv(s, (char*)&magic, sizeof(magic), 0) != sizeof(magic)) goto nack;
	if(magic != PROTO_MAGIC) goto nack;
	if(recv(s, (char*)&version, sizeof(version), 0) != sizeof(version)) goto nack;
	if(version != PROTO_VER) goto nack;
		
	send(s, (char*)&ack, sizeof(ack), 0);

	/* Key Exchange */
	size = sizeof(dh_key_pub);
	send(s, (char*)&size, sizeof(size_t), 0);
	send(s, dh_key_pub, size, 0);

	if(recv(s, (char*)&conn.dh_remote_key_size, 4, 0) != 4)
		return 0;
	
	if((conn.dh_remote_key_size == 0) || (conn.dh_remote_key_size > sizeof(dh_key_p))) /* Remote key invalid */
		goto nack;
		
	if((conn.dh_remote_key = malloc(conn.dh_remote_key_size)) == NULL) goto nack;
	if((recv(s, conn.dh_remote_key, conn.dh_remote_key_size, 0)) != size) goto nack;		
	if(!CheckHash(conn.dh_remote_key, conn.dh_remote_key_size)) goto nack;
		
	send(s, (char*)&ack, sizeof(ack), 0);

	EstablishSharedSecret();

	/* Generating Nonce */
	conn.nonce = malloc(Nb * 4);
	fillbuffer(conn.nonce, Nb * 4, NULL);

	/* Encrypting and sending Nonce */
	aes_InitContext(&context, conn.nonce, conn.dh_shared_key);
	aes_Encrypt(context);
	encnonce = aes_ContextToChar(context);
	send(s, encnonce, Nb * 4, 0);

	free(encnonce);
	aes_FreeContext(context);
	return 1;

nack:
	send(s, (char*)&nack, sizeof(nack), 0);
	return 0;
}

SOCKET CreateConnectSocket(char *remote, int port) {
	SOCKADDR_IN addr;
	SOCKET s;

	s = socket(AF_INET, SOCK_STREAM, 0);

	memset(&addr, 0, sizeof(SOCKADDR_IN));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(SERVER_PORT);
	addr.sin_addr.s_addr = inet_addr(remote);

	if(connect(s, (SOCKADDR*)&addr, sizeof(SOCKADDR)) == SOCKET_ERROR)
		return SOCKET_ERROR;
	
	return s;
}

SOCKET CreateListenSocket(int port) {
	SOCKET s;
	SOCKADDR_IN addr;

	if((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
		return INVALID_SOCKET;

	memset(&addr, 0, sizeof(SOCKADDR_IN));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = ADDR_ANY;
	
	if(bind(s, (SOCKADDR*)&addr, sizeof(SOCKADDR_IN)) == SOCKET_ERROR)
		return SOCKET_ERROR;

	if(listen(s, 10) == SOCKET_ERROR)
		return SOCKET_ERROR;

	return s;
}