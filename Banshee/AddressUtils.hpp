#pragma once

#include <ntifs.h>
#include "Debug.hpp"

ULONG
BeGetAccessTokenOffset();

ULONG
BeGetProcessLinkedListOffset();

PVOID
BeGetBaseAddrOfModule(_In_ PUNICODE_STRING moduleName);

PVOID
BeGetSystemRoutineAddress(
    _In_ CONST PCHAR moduleName,
    _In_ CONST PCHAR functionToResolve
);

UINT16
BeGetEprocessProcessProtectionOffset();