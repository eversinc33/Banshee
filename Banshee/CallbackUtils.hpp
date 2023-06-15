#pragma once

#include "Globals.hpp"
#include "Vector.hpp"

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
		LOG_MSG("Driver: %ls - 0x%llx", entry->BaseDllName.Buffer, entry->DllBase);
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

	while ((PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != first)
	{
		if (UINT64(((PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink)->DllBase) > address)
		{
			return entry;
		}
		entry = (PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
	}

	return NULL;
}

/**
 * Gets the address of the array where kernel callbacks are stored
 * 
 * @return UINT64 address of the ProcessCreateNotifyRoutine array
 */
UINT64
BeGetKernelCallbackArrayAddr_ProcessCreate()
{
	UNICODE_STRING processCreateNotifyRoutineName = RTL_CONSTANT_STRING(L"PsSetCreateProcessNotifyRoutine");
	UINT64 processCreateNotifyRoutineAddr = 0;
	UINT64 psp_processCreateNotifyRoutineAddr = 0;
	UINT64 processCreateNotifyRoutineArrayAddr = 0;

	// Resolve PsSetCreateProcessNotifyRoutine
	processCreateNotifyRoutineAddr = (DWORD64)MmGetSystemRoutineAddress(&processCreateNotifyRoutineName);

	if (!processCreateNotifyRoutineAddr)
	{
		LOG_MSG("Failed to resolve PsSetCreateProcessNotifyRoutine");
		return 0;
	}

	// Now resolve PspSetCreateProcessNotifyRoutine
	// we look for CALL/JMP PspSetCreateProcessNotifyRoutine in the function assembly
	for (INT i = 0; i < 500; ++i)
	{
		if ((*(BYTE*)(processCreateNotifyRoutineAddr + i) == ASM_CALL_NEAR)
			|| (*(BYTE*)(processCreateNotifyRoutineAddr + i) == ASM_JMP_NEAR))
		{
			// param for CALL is offset to our routine
			LOG_MSG("Offset: 0x%lx", *(PUINT32*)(processCreateNotifyRoutineAddr + i + 1));
			UINT32 offset = *(PUINT32)(processCreateNotifyRoutineAddr + i + 1);
			// add offset to addr of next instruction to get psp address
			psp_processCreateNotifyRoutineAddr = processCreateNotifyRoutineAddr + i + offset + 5;
			break;
		}
	}

	if (!psp_processCreateNotifyRoutineAddr)
	{
		LOG_MSG("Failed to resolve Psp(!)SetCreateProcessNotifyRoutine");
		return 0;
	}

	LOG_MSG("PspSetCreateProcessNotifyRoutine: 0x%llx", psp_processCreateNotifyRoutineAddr);

	// Now we resolve the array of callbacks
	// we look for LEA r13 or LEA rcx <addr of callbackArray>
	for (INT i = 0; i < 500; ++i)
	{
		if ((*(BYTE*)(psp_processCreateNotifyRoutineAddr + i) == ASM_LEA_R13_BYTE1 && *(BYTE*)(psp_processCreateNotifyRoutineAddr + i + 1) == ASM_LEA_R13_BYTE2)
			|| (*(BYTE*)(psp_processCreateNotifyRoutineAddr + i) == ASM_LEA_RCX_BYTE1 && *(BYTE*)(psp_processCreateNotifyRoutineAddr + i + 1) == ASM_LEA_RCX_BYTE2))
		{
			// param for LEA is the address of the callback array
			UINT32 offset = *(PUINT32)(psp_processCreateNotifyRoutineAddr + i + 3);
			// add ofset to next instruction to get callback array addr
			processCreateNotifyRoutineArrayAddr = psp_processCreateNotifyRoutineAddr + i + offset + 7;
			break;
		}
	}

	if (!psp_processCreateNotifyRoutineAddr)
	{
		LOG_MSG("Failed to resolve Array for CreateProcess Callbacks");
		return 0;
	}

	return processCreateNotifyRoutineArrayAddr;
}

typedef struct _ProcessCreateCallback {
	PWCHAR driverName;
	UINT64 driverBase;
	UINT64 offset;
} ProcessCreateCallback;

/**
 * Enumerates kernel callbacks set with `PsSetCreateProcessNotifyRoutine`
 * 
 * @returns ktd::vector<ProcessCreateCallback, PagedPool> Vector of callbacks
 */
ktd::vector<ProcessCreateCallback, PagedPool>
BeEnumerateKernelCallbacks_ProcessCreate()
{
	auto data = ktd::vector<ProcessCreateCallback, PagedPool>();

	// get address for the processcreate kernel callback array
	UINT64 arrayAddr = BeGetKernelCallbackArrayAddr_ProcessCreate();
	if (!arrayAddr)
	{
		LOG_MSG("Failed to get array addr for kernel callbacks for processcreate");
		return data;
	}
	LOG_MSG("Array for CreateProcess Callbacks: 0x%llx", arrayAddr);

	for (INT i = 0; i < 32 /* TOOD find out max number of callbacks */; ++i)
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
		ProcessCreateCallback pcc = {
			driver->BaseDllName.Buffer,
			(UINT64)driver->DllBase,
			offset
		};
		data.push_back(pcc);
	}

	return data;
}