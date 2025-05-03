#include "AddressUtils.hpp"
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
    RTL_OSVERSIONINFOW osVersion = { sizeof(osVersion) };
    RtlGetVersion(&osVersion);

    LOG_MSG("Running on %i\n", osVersion.dwBuildNumber);

    ULONG tokenOffset = 0;

    switch (osVersion.dwBuildNumber)
    {
    case WIN_1903:
    case WIN_1909:
        tokenOffset = 0x360;
        break;
    case WIN_1507:
    case WIN_1511:
    case WIN_1607:
    case WIN_1703:
    case WIN_1709:
    case WIN_1803:
    case WIN_1809:
        tokenOffset = 0x358;
        break;
    default:
        tokenOffset = 0x4b8;
        break;
    }

    LOG_MSG("Token offset: %i", tokenOffset);
    return tokenOffset;
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
    RTL_OSVERSIONINFOW osVersion = { sizeof(osVersion) };
    RtlGetVersion(&osVersion);

    LOG_MSG("Running on %i\n", osVersion.dwBuildNumber);

    ULONG activeProcessLinks = 0;

    switch (osVersion.dwBuildNumber)
    {
    case WIN_1507:
    case WIN_1511:
    case WIN_1607:
    case WIN_1903:
    case WIN_1909:
        activeProcessLinks = 0x2f0;
        break;
    case WIN_1703:
    case WIN_1709:
    case WIN_1803:
    case WIN_1809:
        activeProcessLinks = 0x2e8;
        break;
    default:
        activeProcessLinks = 0x448;
        break;
    }

    return activeProcessLinks;
}

/*
 * @brief Retrieves the base address of a module.
 *
 * @param[in] ModuleName Name of the module to retrieve the base address for.
 *
 * @returns PVOID Base address of the module if found, or NULL if not.
 */
PVOID
BeGetBaseAddrOfModule(_In_ PUNICODE_STRING moduleName)
{
    PVOID address = NULL;

    //
    // Acquire the resource in shared mode
    //
    ExAcquireResourceSharedLite(PsLoadedModuleResource, TRUE);

    __try {
        PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)PsLoadedModuleList;
        PKLDR_DATA_TABLE_ENTRY first = entry;

        while ((PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != first)
        {
            if (RtlCompareUnicodeString(&entry->BaseDllName, moduleName, TRUE) == 0)
            {
                address = entry->DllBase;
                break;
            }

            entry = (PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
        }

    }
    __finally
    {
        //
        // Ensure the lock is always released
        //
        ExReleaseResourceLite(PsLoadedModuleResource);
    }

    return address;
}

/*
 * @brief Retrieves the base address of a system module or resolves a function address.
 *
 * @param[in] ModuleName Name of the module to resolve (e.g., "ntoskrnl.exe").
 * @param[in] FunctionToResolve Name of the function to resolve within the module.
 *
 * @returns PVOID Address of the function if found, or NULL if it fails.
 */
PVOID
BeGetSystemRoutineAddress(
    _In_ CONST PCHAR moduleName,
    _In_ CONST PCHAR functionToResolve
)
{
    KAPC_STATE apc = { 0 };
    PVOID      moduleBase = NULL;
    BOOLEAN    inWin32kModule = FALSE;

    if (strcmp(moduleName, "ntoskrnl.exe") == 0)
    {
        moduleBase = BeGlobals::NtOsKrnlAddr;
    }
    else if (strcmp(moduleName, "win32kbase.sys") == 0)
    {
        moduleBase = BeGlobals::Win32kBaseAddr;
        inWin32kModule = TRUE;
    }
    else
    {
        LOG_MSG("ERROR: Invalid module\n");
        return NULL;
    }

    //
    // To read session driver modules, we need to be attached to a process running in a user session 
    // TODO refactor to dedicated function
    // https://www.unknowncheats.me/forum/general-programming-and-reversing/492970-reading-memory-win32kbase-sys.html
    //
    if (inWin32kModule)
    {
        //
        // Attach to winlogon
        //
        KeStackAttachProcess(BeGlobals::winLogonProc, &apc);
    }

    //
    // Parse headers and export directory
    //
    PFULL_IMAGE_NT_HEADERS  ntHeader = (PFULL_IMAGE_NT_HEADERS)((ULONG_PTR)moduleBase + ((PIMAGE_DOS_HEADER)moduleBase)->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)moduleBase + ntHeader->OptionalHeader.DataDirectory[0].VirtualAddress);

    PULONG  addrOfNames = (PULONG)((ULONG_PTR)moduleBase + exportDir->AddressOfNames);
    PULONG  addrOfFuncs = (PULONG)((ULONG_PTR)moduleBase + exportDir->AddressOfFunctions);
    PUSHORT addrOfOrdinals = (PUSHORT)((ULONG_PTR)moduleBase + exportDir->AddressOfNameOrdinals);

    //
    // Look through export directory until function is found and return its address
    //
    for (UINT32 i = 0; i < exportDir->NumberOfNames; ++i)
    {
        PCHAR currentFunctionName = (PCHAR)((ULONG_PTR)moduleBase + (ULONG_PTR)addrOfNames[i]);

        if (strcmp(currentFunctionName, functionToResolve) == 0)
        {
            PULONG addr = (PULONG)((ULONG_PTR)moduleBase + (ULONG_PTR)addrOfFuncs[addrOfOrdinals[i]]);

            LOG_MSG("Found: 0x%llx\n", (ULONG_PTR)addr);

            if (inWin32kModule)
                KeUnstackDetachProcess(&apc);

            return (PVOID)addr;
        }
    }

    if (inWin32kModule)
        KeUnstackDetachProcess(&apc);

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