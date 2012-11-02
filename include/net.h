/* 
 * net.h -- net.c header
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

#include <Windows.h>

#ifndef NET_H_
#define NET_H_

#define PROTO_MAGIC	0x1ca45ce6 
#define	PROTO_VER	0x00000001

#define MSG_ACK		0x3b9ac9ff
#define MSG_NACK	0xc4653600
#define MSG_PING	0x7f54c8a6
#define MSG_PONG	0x80ab3759
#define MSG_SLOG	0x0a72b354
#define MSG_DATA	0xf58d4cab
#define MSG_QUIT	0x18c7bb80
#define MSG_ERR		0x675afc4f

#define SERVER_PORT 31338
#define BUFSIZE 64

typedef struct {
	int dh_remote_key_size;
	unsigned char *dh_remote_key;
	unsigned char *dh_shared_key;
	unsigned char *nonce;
} connection_info_t;

connection_info_t conn;

int StartWinsock(void);
unsigned char *crypt_recv(SOCKET s);
int crypt_send(SOCKET s, unsigned char *data, size_t size);
int recv_msg(SOCKET s);
int send_msg(SOCKET s, int msg);
int ClientHandshake(SOCKET s);
int ServerHandshake(SOCKET s);
SOCKET CreateConnectSocket(char *remote, int port);
SOCKET CreateListenSocket(int port);
void ServerLoop(SOCKET s);

#endif