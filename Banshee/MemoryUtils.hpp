#pragma once

#include <ntifs.h>
#include <wdf.h>
#include <ntddk.h>
#include "Globals.hpp"
#include "Misc.hpp"
#include "WinTypes.hpp"
#include <intrin.h>

/**
 * TODO
 */
NTSTATUS 
BeCreateSharedMemory(HANDLE hSharedMemory, PVOID pSharedMemory)
{
	UNICODE_STRING sectionName;
	OBJECT_ATTRIBUTES objAttributes;
	LARGE_INTEGER sectionSize;
	SIZE_T bufSize = 1024; // TODO

	RtlInitUnicodeString(&sectionName, L"\\Global\\MySharedMemory"); // TODO

	InitializeObjectAttributes(&objAttributes, &sectionName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	sectionSize.QuadPart = bufSize;

	NTSTATUS status = ZwCreateSection(&hSharedMemory, SECTION_ALL_ACCESS, &objAttributes, &sectionSize, PAGE_READWRITE, SEC_COMMIT, NULL);

	if (!NT_SUCCESS(status)) 
	{
		LOG_MSG("Failed to create shared memory: 0x%X\n", status);
		return status;
	}

	// Map the shared memory into kernel address space
	status = ZwMapViewOfSection(hSharedMemory, ZwCurrentProcess(), &pSharedMemory, 0, sectionSize.QuadPart, NULL, &bufSize, ViewUnmap, 0, PAGE_READWRITE);

	if (!NT_SUCCESS(status)) 
	{
		LOG_MSG("Failed to map shared memory: 0x%X\n", status);
		ZwClose(hSharedMemory);
		return status;
	}

	return STATUS_SUCCESS;
}

/**
 * TODO
 */
VOID 
BeCloseSharedMemory(HANDLE hSharedMemory, PVOID pSharedMemory)
{
	if (BeGlobals::pSharedMemory != NULL) 
	{
		ZwUnmapViewOfSection(ZwCurrentProcess(), pSharedMemory);
		BeGlobals::pSharedMemory = NULL;
	}

	if (BeGlobals::hSharedMemory != NULL) 
	{
		ZwClose(hSharedMemory);
		hSharedMemory = NULL;
	}
}

// Disable write protection by setting cr0
KIRQL 
WPOFFx64()
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}

// Enable write protection by setting cr0
VOID 
WPONx64(KIRQL irql)
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}

/*
/**
 * Wrapper for MmCopyVirtualMemory, adjusting permissions accordingly and restoring them
 *
 * @param targetProcess The target process from which data will be read
 * @param procAddr      The source address in the target process from which data will be read
 * @param dstAddr       The addr of the caller process where the data that is read will be written to
 * @param size          The amount of bytes to be read
 * @param accessMode    The access mode specifying whether the operation is in user mode or kernel mode
 *
 * @return              Returns NTSTATUS indicating success or failure
 
NTSTATUS
BeReadProcessMemory(PEPROCESS targetProcess, PVOID procAddr, OUT PVOID dstAddr, SIZE_T size, MODE accessMode)
{
	NTSTATUS NtStatus;

	// TODO: verify addresses according to mode, e.g. kernel mode -> addr must be in kernel space

	SIZE_T bytesRead;
	NtStatus = BeGlobals::pMmCopyVirtualMemory(targetProcess, srcAddr, PsGetCurrentProcess(), dstAddr, size, accessMode, &bytesRead);

	return NtStatus;
}

/**
 * Wrapper for MmCopyVirtualMemory, adjusting permissions accordingly and restoring them
 *
 * @param targetProcess The target process into which data will be written
 * @param srcAddr       The source address in the current process from which data will be copied
 * @param dstAddr       The destination address in the target process where data will be written
 * @param size          The size, in bytes, of the data to be written
 * @param accessMode    The access mode specifying whether the operation is in user mode or kernel mode
 *
 * @return              Returns NTSTATUS indicating success or failure
 
NTSTATUS 
BeWriteProcessMemory(PEPROCESS targetProcess, PVOID srcAddr, PVOID dstAddr, SIZE_T size, MODE accessMode)
{
	NTSTATUS NtStatus;

	// TODO: verify addresses according to mode, e.g. kernel mode -> addr must be in kernel space

	// Aquire handle on target process
	HANDLE hTargetProcess;
	NtStatus = ObOpenObjectByPointer(targetProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, accessMode, &hTargetProcess);
	if (NtStatus != 0)
	{
		return NtStatus;
	}

	// Adjust permissions
	ULONG oldProtection;
	SIZE_T bytesWritten;
	SIZE_T patchLen = size;
	PVOID addressToProtect = dstAddr;
	NtStatus = BeGlobals::pZwProtectVirtualMemory(hTargetProcess, &addressToProtect, &patchLen, PAGE_READWRITE, &oldProtection);
	if (NtStatus != 0) 
	{
		BeGlobals::pZwClose(hTargetProcess);
		return NtStatus;
	}

	// Close handle
	BeGlobals::pZwClose(hTargetProcess);

	// Write shellcode into process
	NtStatus = BeGlobals::pMmCopyVirtualMemory(PsGetCurrentProcess(), srcAddr, targetProcess, dstAddr, size, accessMode, &bytesWritten);

	if (NtStatus != 0)
	{
		return NtStatus;
	}

	// Aquire handle on target process
	NtStatus = ObOpenObjectByPointer(targetProcess, OBJ_KERNEL_HANDLE, NULL, PROCESS_ALL_ACCESS, *PsProcessType, accessMode, &hTargetProcess);
	if (NtStatus != 0)
	{
		return NtStatus;
	}

	// Restore permissions
	patchLen = size;
	NtStatus = BeGlobals::pZwProtectVirtualMemory(hTargetProcess, &addressToProtect, &patchLen, oldProtection, &oldProtection);
	if (NtStatus != 0)
	{
		BeGlobals::pZwClose(hTargetProcess);
		return NtStatus;
	}

	// Close handle
	NtStatus = BeGlobals::pZwClose(hTargetProcess);

	return STATUS_SUCCESS;
}
*/