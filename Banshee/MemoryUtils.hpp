#pragma once

#pragma comment(lib, "Ksecdd.lib")

#include <ntifs.h>
#include <wdf.h>
#include <ntddk.h>
#include <intrin.h>
#include "WinTypes.hpp"
#include "ProcessUtils.hpp"
#include "Misc.hpp"

NTSTATUS
BeCreateSharedMemory();

VOID
BeCloseSharedMemory(
    _In_ HANDLE hSharedMemory,
    _In_ PVOID pSharedMemory
);

KIRQL
WPOFFx64();

VOID
WPONx64(
    _In_ KIRQL irql
);