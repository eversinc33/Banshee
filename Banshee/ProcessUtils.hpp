#pragma once

#include <ntifs.h>
#include <wdf.h>
#include "Globals.hpp"
#include "WinTypes.hpp"

// TODO doc
// https://www.unknowncheats.me/forum/general-programming-and-reversing/572734-pid-process-name.html
HANDLE Get_pid_from_name(const UNICODE_STRING& processName) {

    NTSTATUS status = STATUS_SUCCESS;
    ULONG bufferSize = 0;
    PVOID buffer = NULL;

    PSYSTEM_PROCESS_INFORMATION pCurrent = NULL;

    status = BeGlobals::pZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
    if (status == STATUS_INFO_LENGTH_MISMATCH)
    {
        buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, DRIVER_TAG);
        if (buffer == NULL)
        {
            return pCurrent;
        }
        else
        {
            status = BeGlobals::pZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
            if (!NT_SUCCESS(status)) {
                ExFreePoolWithTag(buffer, DRIVER_TAG);
                return pCurrent;
            }
        }
    }

    pCurrent = (PSYSTEM_PROCESS_INFORMATION)buffer;
    while (pCurrent) {
        if (pCurrent->ImageName.Buffer != NULL)
        {
            if (RtlCompareUnicodeString(&(pCurrent->ImageName), &processName, TRUE) == 0)
            {
                ExFreePoolWithTag(buffer, DRIVER_TAG);
                return pCurrent->ProcessId;
            }
        }
        if (pCurrent->NextEntryOffset == 0) {
            pCurrent = NULL;
        }
        else {
            pCurrent = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pCurrent) + pCurrent->NextEntryOffset);
        }
    }

    return pCurrent;
}


/**
 * Checks whether a process with the given pid exists and returns a pointer to the EPROCESS object
 *
 * @param pid Pid of the process to check
 * @returns PEPROCESS pointer to the EPROCESS object or NULL if not existing
 */
PEPROCESS
BeGetEprocessByPid(IN ULONG pid)
{
    PEPROCESS process;
    if (PsLookupProcessByProcessId(ULongToHandle(pid), &process) != 0)
    {
        LOG_MSG("PID %i not found \r\n", (ULONG)pid);
        ObDereferenceObject(process);
        return NULL;
    }
    return process;
}