#pragma once

#include <ntifs.h>
#include <wdf.h>
#include "WinTypes.hpp"

HANDLE
BeGetPidFromProcessName(
    _In_ CONST UNICODE_STRING& processName
);

PEPROCESS
BeGetEprocessByPid(
    _In_ ULONG pid
);