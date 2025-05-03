#pragma once

#include <ntifs.h>
#include <wdf.h>
#include "Vector.hpp"
#include "WinTypes.hpp"
#include "MemoryUtils.hpp"

VOID
BeEnumerateDrivers();

PKLDR_DATA_TABLE_ENTRY
BeGetDriverForAddress(
    _In_ UINT64 address
);

UINT64
BeGetKernelCallbackArrayAddr(
    _In_ CALLBACK_TYPE type
);

ktd::vector<CALLBACK_DATA, PagedPool>
BeEnumerateKernelCallbacks(_In_ CALLBACK_TYPE Type);

VOID
BeEmptyCreateProcessNotifyRoutine(
    _In_ HANDLE  parentId,
    _In_ HANDLE  processId,
    _In_ BOOLEAN create
);

VOID
BeEmptyCreateThreadNotifyRoutine(
    _In_ HANDLE  processId,
    _In_ HANDLE  threadId,
    _In_ BOOLEAN create
);

NTSTATUS
BeReplaceKernelCallbacksOfDriver(
    _In_ PWCH targetDriverModuleName,
    _In_ CALLBACK_TYPE type
);