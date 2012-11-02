#include <WinSock2.h>
#include <stdio.h>

#include "..\include\net.h"

#define REMOTE_ADDR "127.0.0.1"
/* 
 * client.c -- Logger client main source file
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

#define LOGFILE "remotelog.txt"

static void recv_log(SOCKET s) {
	FILE *fp;
	int blocks = 0, i;
	unsigned char *buf;

	if((fp = fopen(LOGFILE, "w")) == NULL)
		return;

	recv(s, (char*)&blocks, sizeof(blocks), 0);
	printf(" Blocks: %d\n", blocks);

	for(i = 0; i < blocks; i++) {
		buf = crypt_recv(s);
		fwrite(buf, BUFSIZE, 1, fp);
		free(buf);
	}
	recv(s, (char*)&blocks, sizeof(blocks), 0);
	if(blocks == 0)
		printf(" Done.\n");
	else
		printf(" Error.\n");
	fclose(fp);
}

static void CommandLoop(SOCKET s) {
	int c, d, msg, sent, active = 1;

	printf("Commands:\np: ping\ns: send log\nq: quit server\ne: exit client\n\n");

	do {
		sent = 1;		
		c = getchar();
		if(c == '\n')
			continue;

		switch(c) {
			case 'p':
				send_msg(s, MSG_PING);
				break;
			case 's':
				send_msg(s, MSG_SLOG);				
				break;
			case 'q':				
				d = getchar();
				if(d == '!') {
					send_msg(s, MSG_QUIT);
					active = 0;
				} else {
					printf("Use 'q!' if you are sure.\n");
					sent = 0;
				}
				break;
			case 'e':
			case EOF:
				active = 0;
			default:
				sent = 0;
		}
		if(sent) {
			msg = recv_msg(s);
			printf("Server: ");
			switch(msg) {
				case MSG_ACK: printf("ACK\n"); break;
				case MSG_NACK: printf("NACK\n"); break;
				case MSG_PONG: printf("PONG!\n"); break;
				case MSG_DATA: 
					printf("Sending Data...\n");
					recv_log(s);
					break;
				default:
					printf("Code %08x\n", msg);			
			}
		}
	} while(active);
}

int main(int argc, char **argv) {
	SOCKET s;
	char *remote;

	if(argc > 1)
		remote = argv[1];
	else
		remote = REMOTE_ADDR;
	
	printf("Starting Winsock... ");
	if(StartWinsock() != 0) {
		printf("Failed.\n");
		return EXIT_FAILURE;
	}
	printf("OK.\n");

	printf("Connecting to %s:%d... ", remote, SERVER_PORT);

	if((s = CreateConnectSocket(remote, SERVER_PORT)) == SOCKET_ERROR) {
		printf("Failed.\n");
		return EXIT_FAILURE;
	}
	printf("OK.\n\n");

	if(ClientHandshake(s))
		CommandLoop(s);

	WSACleanup();
	return EXIT_SUCCESS;
}