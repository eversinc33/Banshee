#pragma once

#include <ntifs.h>
#include <wdf.h>
#include "Globals.hpp"
#include "Misc.hpp"
#include "WinTypes.hpp"

/**
 * Enumerates loaded drivers by parsing the driver section inloadorder linked list
 */
VOID
BeEnumerateDrivers()
{
    PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)(BeGlobals::driverObject)->DriverSection;
    PKLDR_DATA_TABLE_ENTRY first = entry;

    while ((PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != first)
    {
		LOG_MSG("Driver: 0x%llx :: %ls", entry->DllBase, entry->BaseDllName.Buffer);
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
	PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)(BeGlobals::driverObject)->DriverSection;
	PKLDR_DATA_TABLE_ENTRY first = entry;

	LOG_MSG("Looking for address: 0x%llx", address);

	// HACK: TODO: drivers are not sorted by address, so i do stupid shit here
	PKLDR_DATA_TABLE_ENTRY currentBestMatch = NULL;
	while ((PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != first)
	{
		UINT64 startAddr = UINT64(entry->DllBase);
		UINT64 endAddr = UINT64(((PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink)->DllBase);
		if (address >= startAddr && (currentBestMatch == NULL || startAddr > UINT64(currentBestMatch->DllBase)))
		{
			currentBestMatch = entry;
		}
		entry = (PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
	}

	return currentBestMatch;
}

/**
 * Gets the address of the array where kernel callbacks are stored
 * 
 * @param type Type of callback to resolve
 * @return UINT64 address of the callbackRoutine array
 */
UINT64
BeGetKernelCallbackArrayAddr(CALLBACK_TYPE type)
{
	BeEnumerateDrivers();
	UNICODE_STRING callbackRoutineName;

	switch (type)
	{
	case CreateProcessNotifyRoutine:
		callbackRoutineName = RTL_CONSTANT_STRING(L"PsSetCreateProcessNotifyRoutine");
		break;
	case CreateThreadNotifyRoutine:
		callbackRoutineName = RTL_CONSTANT_STRING(L"PsSetCreateThreadNotifyRoutine");
		break;
	default:
		LOG_MSG("Unsupported callback type");
		return 0;
	}

	UINT64 callbackRoutineAddr = 0;
	UINT64 psp_callbackRoutineAddr = 0;
	UINT64 callbackRoutineArrayAddr = 0;

	if (type == CreateProcessNotifyRoutine || type == CreateThreadNotifyRoutine)
	{
		// Resolve PsSetCreateXYZNotifyRoutine TODO: use own implementation here
		callbackRoutineAddr = (DWORD64)MmGetSystemRoutineAddress(&callbackRoutineName);

		if (!callbackRoutineAddr)
		{
			LOG_MSG("Failed to resolve set-notify routine");
			return 0;
		}

		// Now resolve PspSetCreateXYZNotifyRoutine
		// we look for CALL/JMP PspSetCreateXYZNotifyRoutine in the function assembly
		for (INT i = 0; i < 500; ++i)
		{
			if ((*(BYTE*)(callbackRoutineAddr + i) == ASM_CALL_NEAR)
				|| (*(BYTE*)(callbackRoutineAddr + i) == ASM_JMP_NEAR))
			{
				// param for CALL is offset to our routine
				LOG_MSG("Offset: 0x%lx", *(PUINT32*)(callbackRoutineAddr + i + 1));
				UINT32 offset = *(PUINT32)(callbackRoutineAddr + i + 1);
				// add offset to addr of next instruction to get psp address
				psp_callbackRoutineAddr = callbackRoutineAddr + i + offset + 5;
				break;
			}
		}

		if (!psp_callbackRoutineAddr)
		{
			LOG_MSG("Failed to resolve private setnotify routine");
			return 0;
		}

		LOG_MSG("Private (psp) NotifyRoutine: 0x%llx", psp_callbackRoutineAddr);

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
			LOG_MSG("Failed to resolve Array for callbacks");
			return 0;
		}

		return callbackRoutineArrayAddr;
	}
}

typedef struct _KernelCallback {
	PWCHAR driverName;
	UINT64 driverBase;
	UINT64 offset;
} KernelCallback;

/**
 * Enumerates kernel callbacks set 
 * 
 * @param type Type of callback to resolve
 * @returns ktd::vector<KernelCallback, PagedPool> Vector of callbacks
 */
ktd::vector<KernelCallback, PagedPool>
BeEnumerateKernelCallbacks(CALLBACK_TYPE type)
{
	auto data = ktd::vector<KernelCallback, PagedPool>();

	// get address for the kernel callback array
	UINT64 arrayAddr = BeGetKernelCallbackArrayAddr(type);
	if (!arrayAddr)
	{
		LOG_MSG("Failed to get array addr for kernel callbacks");
		return data;
	}
	LOG_MSG("Array for callbacks: 0x%llx", arrayAddr);

	for (INT i = 0; i < 16; ++i) // TODO: max number
	{
		// get current address & align the addresses to 0x10 (https://medium.com/@yardenshafir2/windbg-the-fun-way-part-2-7a904cba5435)
		PVOID currCallbackBlockAddr = (PVOID)(((UINT64*)arrayAddr)[i] & 0xFFFFFFFFFFFFFFF0);

		if (!currCallbackBlockAddr)
			continue;

		// cast to callback routine block
		EX_CALLBACK_ROUTINE_BLOCK currCallbackBlock = *((EX_CALLBACK_ROUTINE_BLOCK*)currCallbackBlockAddr);

		// get function address
		UINT64 callbackFunctionAddr = (UINT64)currCallbackBlock.Function;

		// get corresponding driver
		PKLDR_DATA_TABLE_ENTRY driver = BeGetDriverForAddress(callbackFunctionAddr);

		if (!driver)
		{
			LOG_MSG("Didnt find driver for callback");
			continue;
		}

		// calculate offset of function
		UINT64 offset = callbackFunctionAddr - (UINT64)(driver->DllBase);

		// Print info
		LOG_MSG("Callback: %ls, 0x%llx + 0x%llx", driver->BaseDllName.Buffer, (UINT64)driver->DllBase, offset);

		// add to result data
		KernelCallback pcc = {
			driver->BaseDllName.Buffer,
			(UINT64)driver->DllBase,
			offset
		};
		data.push_back(pcc);
	}

	return data;
}