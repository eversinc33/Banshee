#pragma once

#include "WinTypes.hpp"
#include "FileUtils.hpp"
#include "ProcessUtils.hpp"

NTSTATUS
GetSsn(
    _In_  LPCSTR  Function,
    _Out_ PUSHORT Ssn
);

PVOID
FindZwFunction(
    _In_ LPCSTR Name
);

NTSTATUS
BeInjectionShellcode(
    _In_ ULONG  Pid,
    _In_ PCWSTR FilePath
);