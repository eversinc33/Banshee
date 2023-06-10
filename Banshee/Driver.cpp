#include <ntifs.h>
#include <wdf.h>

#include "DriverMeta.hpp"
#include "Globals.hpp"
#include "IOCTLS.hpp"

// --------------------------------------------------------------------------------------------------------

/**
 * Called on unloading the driver.
 *
 * @param DriverObject Pointer to the DriverObject.
 * @return NTSTATUS status code.
 */
NTSTATUS
BeUnload(PDRIVER_OBJECT DriverObject)
{
    DbgPrint("Unload Called \r\n");

    // Remove our bury routine if we set one
    if(BeGlobals::beBuryTargetProcesses.length != 0)
    {
        if (PsSetCreateProcessNotifyRoutineEx(BeBury_ProcessNotifyRoutineEx, TRUE) == STATUS_SUCCESS)
        {
            DbgPrint("Removed routine!\n");
        }
        else
        {
            DbgPrint("Failed to remove routine!\n");
        }
        // free global memory for bury process wstrs
        ExAcquireFastMutex(&BeGlobals::beBuryMutex); // wait for any currently running callbacks that access the array to finish
        while(BeGlobals::beBuryTargetProcesses.length >= 0)
        {
            if (BeGlobals::beBuryTargetProcesses.array[BeGlobals::beBuryTargetProcesses.length] != NULL)
            {
                ExFreePoolWithTag(BeGlobals::beBuryTargetProcesses.array[BeGlobals::beBuryTargetProcesses.length], DRIVER_TAG);
                BeGlobals::beBuryTargetProcesses.array[BeGlobals::beBuryTargetProcesses.length] = NULL;
            }
            BeGlobals::beBuryTargetProcesses.length--;
        }
        ExReleaseFastMutex(&BeGlobals::beBuryMutex);
    }
        
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
    DbgPrint("Close Called \r\n");
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
    DbgPrint("Create Called \r\n");
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
    DbgPrint("DriverEntry Called \r\n");

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

    pDriverObject->DriverUnload = (PDRIVER_UNLOAD)BeUnload;

    // IRP Major Requests
    for (ULONG uiIndex = 0; uiIndex < IRP_MJ_MAXIMUM_FUNCTION; uiIndex++)
    {
        pDriverObject->MajorFunction[uiIndex] = (PDRIVER_DISPATCH)BeUnSupportedFunction;
    }
    pDriverObject->MajorFunction[IRP_MJ_CLOSE] = (PDRIVER_DISPATCH)BeClose;               // CloseHandle
    pDriverObject->MajorFunction[IRP_MJ_CREATE] = (PDRIVER_DISPATCH)BeCreate;             // CreateFile
    pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)BeIoControl;  // DeviceIoControl
    
    // Init globals
    BeGlobals::BeInitGlobals(pDriverObject);

    NtStatus = IoCreateSymbolicLink(&usDosDeviceName, &usDriverName); // Symbolic Link simply maps a DOS Device Name to an NT Device Name.

    return NtStatus;
}
