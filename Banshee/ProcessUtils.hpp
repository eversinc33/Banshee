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
        LOG_MSG("PID %i not found \r\n", (ULONG)pid);
        return NULL;
    }
    return process;
}