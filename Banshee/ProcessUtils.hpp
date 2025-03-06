#pragma once

#include <ntifs.h>
#include <wdf.h>
#include "Globals.hpp"
#include "WinTypes.hpp"

/*
 * @brief Retrieves the PID of the first matching process by name.
 * https://www.unknowncheats.me/forum/general-programming-and-reversing/572734-pid-process-name.html
 * 
 * @param[in] ProcessName Name of the process to look up.
 *
 * @returns HANDLE Process ID of the matching process, or NULL if not found.
 */
HANDLE 
BeGetPidFromProcessName(
    _In_ CONST UNICODE_STRING& processName
)
{
    NTSTATUS status     = STATUS_SUCCESS;
    ULONG    bufferSize = 0;
    PVOID    buffer     = NULL;

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
            if (!NT_SUCCESS(status))
            {
                ExFreePoolWithTag(buffer, DRIVER_TAG);
                return pCurrent;
            }
        }
    }

    pCurrent = (PSYSTEM_PROCESS_INFORMATION)buffer;
    while (pCurrent) 
    {
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
        else 
        {
            pCurrent = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pCurrent) + pCurrent->NextEntryOffset);
        }
    }

    return pCurrent;
}

/*
 * @brief Retrieves the EPROCESS pointer for a given PID.
 *
 * @param[in] Pid PID of the process to retrieve.
 *
 * @returns PEPROCESS Pointer to the EPROCESS object, or NULL if not found.
 */
PEPROCESS
BeGetEprocessByPid(
    _In_ ULONG pid
)
{
    PEPROCESS pProcess;
    if (PsLookupProcessByProcessId(ULongToHandle(pid), &pProcess) != 0)
    {
        LOG_MSG("PID %i not found \r\n", (ULONG)pid);
        return NULL;
    }

    return pProcess;
}