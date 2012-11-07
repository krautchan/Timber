/* 
 * client.c -- Logger client main source file
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

#include <WinSock2.h>
#include <stdio.h>

#include "..\include\net.h"
#include "..\include\memory.h"

#define REMOTE_ADDR "127.0.0.1"

#define LOGFILE "remotelog.txt"

static void RecvLog(SOCKET s) {
	FILE *fp;
	int blocks = 0, i;
	unsigned char *buf;

	if((fp = fopen(LOGFILE, "w")) == NULL)
		return;

	recv(s, (char*)&blocks, sizeof(blocks), 0);
	printf(" Blocks: %d\n", blocks);

	for(i = 0; i < blocks; i++) {
		buf = CryptRecvData(s);
		fwrite(buf, 1, BUFSIZE, fp);
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
	int c, d, sent, active = 1;
	message_t msg;

	printf("Commands:\np: ping\ni: query install level\ns: send log\nq: quit server\ne: exit client\n\n");

	do {
		sent = 1;		
		c = getchar();
		if(c == '\n')
			continue;

		switch(c) {
			case 'p':
				CryptSendMsg(s, MSG_PING, 0);
				break;
			case 'i':
				CryptSendMsg(s, MSG_QUIN, 0);
				break;
			case 's':
				CryptSendMsg(s, MSG_SLOG, 0);				
				break;
			case 'q':				
				d = getchar();
				if(d == '!') {
					CryptSendMsg(s, MSG_QUIT, 0);
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
			msg = CryptRecvMsg(s);
			printf("Server: ");
			switch(msg.msg) {
				case MSG_ACK: printf("ACK\n"); break;
				case MSG_NACK: printf("NACK\n"); break;
				case MSG_PONG: printf("PONG!\n"); break;
				case MSG_QUIN:
					printf("Level = %d (", msg.arg);
					switch(msg.arg) {
						case 0:	printf("Not installed)\n"); break;
						case 1: printf("Installed, but not automatically run)\n"); break;
						case 2: printf("Run for local user)\n"); break;
						case 3: printf("Run system-wide)\n"); break;
						case 4: printf("Run as service)\n"); break;
						default: printf("Unknown ilevel)\n"); break;
					}
					break;
				case MSG_DATA: 
					printf("Sending Data...\n");
					RecvLog(s);
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

	if(conn.dh_remote_key)
		free(conn.dh_remote_key);
	if(conn.dh_shared_key)
		free(conn.dh_shared_key);
	if(conn.nonce)
		free(conn.nonce);

#ifdef _DEBUG
	showmemstats(stdout);
#endif

	return EXIT_SUCCESS;
}