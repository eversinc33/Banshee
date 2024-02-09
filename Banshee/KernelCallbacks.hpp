#pragma once

#include <ntifs.h>
#include <wdf.h>
#include "Globals.hpp"
#include "WinTypes.hpp"
#include "Misc.hpp"

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

    { // LOCK
        AutoLock<FastMutex> _lock(BeGlobals::buryLock);

        if (CreateInfo) // If new process is created ...
        {
            LOG_MSG("Process Creation %i: %wZ \r\n", HandleToUlong(ProcessId), CreateInfo->ImageFileName);

            // ... check for each process
            for (INT i = 0; i < BeGlobals::beBuryTargetProcesses.length; ++i)
            {
                if (!BeIsStringNull(BeGlobals::beBuryTargetProcesses.array[i]))
                {
                    // ... if its one we want to bury ...
                    if (StrStrIW(
                        CreateInfo->ImageFileName->Buffer,
                        BeGlobals::beBuryTargetProcesses.array[i]
                    ) != NULL)
                    {
                        LOG_MSG("Blocking buried process from starting. \r\n");
                        // ... then block it by setting the creation status to denied
                        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
                    }
                }
            }
        }
    } // LOCK END
}