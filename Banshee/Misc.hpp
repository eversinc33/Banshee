#pragma once

#include <ntifs.h>
#include "DriverMeta.hpp"

BOOLEAN
BeIsStringNull(
    _In_ PWCHAR pWchar
);

BOOLEAN
BeIsStringTerminated(
    _In_ PWCHAR array,
    _In_ ULONG arrayLength
);

NTSTATUS
BeCheckStringIsAlignedNotEmptyAndTerminated(
    _In_ PWCHAR targetString,
    _In_ ULONG size
);

PWCHAR
StrStrIW(
    _In_ CONST PWCHAR string,
    _In_ CONST PWCHAR pattern
);

PCHAR
GetBaseNameFromFullPath(
    _In_ PCHAR fullName
);

NTSTATUS
BeCreateSecurityDescriptor(
    _Out_ PSECURITY_DESCRIPTOR* sd
);

NTSTATUS
BeSetNamedEvent(
    _In_ HANDLE  hEvent,
    _In_ BOOLEAN set
);

NTSTATUS
BeWaitForEvent(
    _In_ HANDLE hEvent
);

NTSTATUS
BeCreateNamedEvent(
    _Out_ PHANDLE         phEvent,
    _In_  PUNICODE_STRING eventName,
    _In_  BOOLEAN         initialSignaledState
);