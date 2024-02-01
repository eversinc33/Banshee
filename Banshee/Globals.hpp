#pragma once

#include <ntifs.h>
#include <wdf.h>
#include "WinTypes.hpp"

namespace BeGlobals
{
    PVOID NtOsKrnlAddr;
    PDRIVER_OBJECT driverObject;
}

#include "AddressUtils.hpp"

#define MAX_BURIED_PROCESSES 256

typedef struct _WCHAR_ARRAY {
    WCHAR* array[MAX_BURIED_PROCESSES];
    INT length;
} WCHAR_ARRAY;

// Function Prototypes
typedef NTSTATUS(*ZWTERMINATEPROCESS)(IN HANDLE ProcessHandle OPTIONAL, IN NTSTATUS ExitStatus);
typedef NTSTATUS(*ZWOPENPROCESS)(OUT PHANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN PCLIENT_ID ClientId);
typedef NTSTATUS(*ZWCLOSE)(IN HANDLE Handle);

namespace BeGlobals
{
    WCHAR_ARRAY beBuryTargetProcesses = { { NULL }, 0 };
    FAST_MUTEX beBuryMutex;

    ZWTERMINATEPROCESS pZwTerminateProcess;
    ZWOPENPROCESS pZwOpenProcess;
    ZWCLOSE pZwClose;

    VOID
    BeInitGlobals(PDRIVER_OBJECT DriverObject)
    {
        // globals
        driverObject = DriverObject;

        // Init mutexes
        ExInitializeFastMutex(&beBuryMutex);

        // Get base address of ntoskrnl module
        NtOsKrnlAddr = BeGetKernelBaseAddr();
        LOG_MSG("ntoskrnl.exe base addr:0x%llx\n", (UINT64)NtOsKrnlAddr);

        // Function resolving
        pZwTerminateProcess = (ZWTERMINATEPROCESS)BeGetSystemRoutineAddress("ZwTerminateProcess");
        pZwOpenProcess = (ZWOPENPROCESS)BeGetSystemRoutineAddress("ZwOpenProcess");
        pZwClose = (ZWCLOSE)BeGetSystemRoutineAddress("ZwClose");
        if (!pZwTerminateProcess || !pZwOpenProcess || !pZwClose)
        {
            LOG_MSG("Failed to resolve Zw function!\n");
        }
        LOG_MSG("ZwTerm: 0x%llx\n", (UINT64)ZwTerminateProcess);
    }
}

