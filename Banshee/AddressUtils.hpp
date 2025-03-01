#pragma once

#include <ntifs.h>
#include <wdf.h>
#include "Globals.hpp"
#include "WinTypes.hpp"
#include "DriverMeta.hpp"
#include "ProcessUtils.hpp"

/**
 * @brief Get offset to the access token from the EPROCESS structure, depending on the OS version.
 * Taken from https://github.com/Idov31/Nidhogg/blob/2776908e86c34771d0663e931b1930c64a9d4b15/Nidhogg/WindowsTypes.hpp
 *
 * @return ULONG Offset to Acess Token.
 */
ULONG
BeGetAccessTokenOffset()
{
    RTL_OSVERSIONINFOW OsVersion = { sizeof(OsVersion) };
    RtlGetVersion(&OsVersion);

    LOG_MSG("Running on %i\n", OsVersion.dwBuildNumber);

    ULONG TokenOffset = 0;

    switch (OsVersion.dwBuildNumber)
    {
    case WIN_1903:
    case WIN_1909:
        TokenOffset = 0x360;
        break;
    case WIN_1507:
    case WIN_1511:
    case WIN_1607:
    case WIN_1703:
    case WIN_1709:
    case WIN_1803:
    case WIN_1809:
        TokenOffset = 0x358;
        break;
    default:
        TokenOffset = 0x4b8;
        break;
    }

    LOG_MSG("Token offset: %i", TokenOffset);
    return TokenOffset;
}

/**
 * @brief Get offset to the process list from the EPROCESS structure, depending on the OS version.
 * Taken from https://github.com/Idov31/Nidhogg/blob/2776908e86c34771d0663e931b1930c64a9d4b15/Nidhogg/WindowsTypes.hpp
 *
 * @return ULONG Offset to Process List.
 */
ULONG
BeGetProcessLinkedListOffset()
{
    RTL_OSVERSIONINFOW OsVersion = { sizeof(OsVersion) };
    RtlGetVersion(&OsVersion);

    LOG_MSG("Running on %i\n", OsVersion.dwBuildNumber);

    ULONG ActiveProcessLinks = 0;

    switch (OsVersion.dwBuildNumber)
    {
    case WIN_1507:
    case WIN_1511:
    case WIN_1607:
    case WIN_1903:
    case WIN_1909:
        ActiveProcessLinks = 0x2f0;
        break;
    case WIN_1703:
    case WIN_1709:
    case WIN_1803:
    case WIN_1809:
        ActiveProcessLinks = 0x2e8;
        break;
    default:
        ActiveProcessLinks = 0x448;
        break;
    }

    return ActiveProcessLinks;
}

/*
 * @brief Retrieves the base address of a module.
 *
 * @param[in] ModuleName Name of the module to retrieve the base address for.
 *
 * @returns PVOID Base address of the module if found, or NULL if not.
 */
PVOID
BeGetBaseAddrOfModule(_In_ PUNICODE_STRING ModuleName) 
{
    PVOID Address = NULL;

    //
    // Acquire the resource in shared mode
    //
    ExAcquireResourceExclusiveLite(PsLoadedModuleResource, TRUE);

    __try {
        PKLDR_DATA_TABLE_ENTRY Entry = (PKLDR_DATA_TABLE_ENTRY)PsLoadedModuleList;
        PKLDR_DATA_TABLE_ENTRY First = Entry;

        while ((PKLDR_DATA_TABLE_ENTRY)Entry->InLoadOrderLinks.Flink != First)
        {
            if (RtlCompareUnicodeString(&Entry->BaseDllName, ModuleName, TRUE) == 0)
            {
                Address = Entry->DllBase;
                break;
            }

            Entry = (PKLDR_DATA_TABLE_ENTRY)Entry->InLoadOrderLinks.Flink;
        }

    }
    __finally {
        //
        // Ensure the lock is always released
        //
        ExReleaseResourceLite(PsLoadedModuleResource);
    }

    return Address;
}

/*
 * @brief Retrieves the base address of a system module.
 *
 * @param[in] ModuleName Name of the module to resolve (e.g., "ntoskrnl.exe").
 * @param[in] FunctionToResolve Name of the function to resolve within the module.
 *
 * @returns PVOID Address of the function if found, or NULL if it fails.
 */
PVOID
BeGetSystemRoutineAddress(
    _In_ CONST PCHAR ModuleName,
    _In_ CONST PCHAR FunctionToResolve
) {
    KAPC_STATE Apc            = { 0 };
    PVOID      ModuleBase     = NULL;
    BOOLEAN    InWin32kModule = FALSE;

    if (strcmp(ModuleName, "ntoskrnl.exe") == 0) {
        ModuleBase = BeGlobals::NtOsKrnlAddr;
    }
    else if (strcmp(ModuleName, "win32kbase.sys") == 0) {
        ModuleBase = BeGlobals::Win32kBaseAddr;
        InWin32kModule = TRUE;
    }
    else {
        LOG_MSG("ERROR: Invalid module\n");
        return NULL;
    }

    //
    // To read session driver modules, we need to be attached to a process running in a user session // TODO refactor to dedicated function
    // https://www.unknowncheats.me/forum/general-programming-and-reversing/492970-reading-memory-win32kbase-sys.html
    //
    if (InWin32kModule)
    {
        //
        // Attach to winlogon
        //
        KeStackAttachProcess(BeGlobals::winLogonProc, &Apc);
    }

    //
    // Parse headers and export directory
    //
    PFULL_IMAGE_NT_HEADERS  NtHeader  = (PFULL_IMAGE_NT_HEADERS)((ULONG_PTR)ModuleBase + ((PIMAGE_DOS_HEADER)ModuleBase)->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)ModuleBase + NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress);

    PULONG  AddrOfNames    = (PULONG)((ULONG_PTR)ModuleBase + ExportDir->AddressOfNames);
    PULONG  AddrOfFuncs    = (PULONG)((ULONG_PTR)ModuleBase + ExportDir->AddressOfFunctions);
    PUSHORT AddrOfOrdinals = (PUSHORT)((ULONG_PTR)ModuleBase + ExportDir->AddressOfNameOrdinals);

    //
    // Look through export directory until function is found and return its address
    //
    for (UINT32 I = 0; I < ExportDir->NumberOfNames; ++I)
    {
        PCHAR CurrentFunctionName = (PCHAR)((ULONG_PTR)ModuleBase + (ULONG_PTR)AddrOfNames[I]);

        if (strcmp(CurrentFunctionName, FunctionToResolve) == 0)
        {
            PULONG Addr = (PULONG)((ULONG_PTR)ModuleBase + (ULONG_PTR)AddrOfFuncs[AddrOfOrdinals[I]]);

            LOG_MSG("Found: 0x%llx\n", (ULONG_PTR)Addr);

            if (InWin32kModule)
                KeUnstackDetachProcess(&Apc);

            return (PVOID)Addr;
        }
    }

    if (InWin32kModule)
        KeUnstackDetachProcess(&Apc);

    //
    // Else return null
    //
    return NULL;
}
/*
 * Gets offset of EPROCESS ProcessProtection dynamically by parsing PsIsProtectedProcessLight.
 * Shoutout to @never_unsealed and @C5Pider for pointing this out to me.
 *
 * @returns ULONG Offset of EPROCESS ProcessProtection
 */
UINT16
BeGetEprocessProcessProtectionOffset()
{
    return (UINT16)(*((PUINT16)BeGetSystemRoutineAddress("ntoskrnl.exe", "PsIsProtectedProcessLight") + 0x1));
}