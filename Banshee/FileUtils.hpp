#pragma once

#include <ntifs.h>
#include <wdf.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <ntdef.h>
#include "WinTypes.hpp"

PWCH
BeGetFilenameFromPath(
    _In_ PWCH fullPath
);

NTSTATUS
BeGetNtfsDriverObject(
    _Out_ PDRIVER_OBJECT* pNtfsDriverObject
);

NTSTATUS
BeReadFile(
    _In_  PCWSTR  filePath,
    _Out_ PVOID* outBuffer,
    _Out_ PSIZE_T outsize
);

#if DENY_DRIVER_FILE_ACCESS
NTSTATUS
BeHooked_NTFS_IRP_MJ_CREATE(PDEVICE_OBJECT DeviceObject, PIRP Irp);

NTSTATUS
BeHookNTFSFileCreate();

NTSTATUS
BeUnhookNTFSFileCreate();
#endif 