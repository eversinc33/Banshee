#pragma once

#include <ntifs.h>
#include <wdf.h>
#include "WinTypes.hpp"
#include "AddressUtils.hpp"

#define MAX_BURIED_PROCESSES 256

typedef struct _WCHAR_ARRAY {
    WCHAR* array[MAX_BURIED_PROCESSES];
    INT length;
} WCHAR_ARRAY;

namespace BeGlobals
{
    WCHAR_ARRAY beBuryTargetProcesses = { { NULL }, 0};
    FAST_MUTEX beBuryMutex;
    PVOID NtOsKrnlAddr;

    VOID
    BeInitGlobals(PDRIVER_OBJECT DriverObject)
    {
        // Init mutexes
        ExInitializeFastMutex(&beBuryMutex);
       
        // Get base address of ntoskrnl module
        NtOsKrnlAddr = BeGetKernelBaseAddr(DriverObject);
        DbgPrint("notskrnl.exe base addr:0x%llx", (UINT64)NtOsKrnlAddr);
    }
}

