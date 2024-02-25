#pragma once

#include <ntifs.h>
#include <wdf.h>
#include "Globals.hpp"
#include "Misc.hpp"
#include "WinTypes.hpp"
#include "DriverMeta.hpp"
#include "ProcessUtils.hpp"

enum ModuleName 
{
    NtOsKrnl = 0,
    Win32kBase = 1
};

/**
 * Get offset to the access token from the EPROCESS structure, depending on the OS version.
 * Taken from https://github.com/Idov31/Nidhogg/blob/2776908e86c34771d0663e931b1930c64a9d4b15/Nidhogg/WindowsTypes.hpp
 *
 * @return ULONG Offset to Acess Token.
 */
ULONG
BeGetAccessTokenOffset()
{
    RTL_OSVERSIONINFOW osVersion = { sizeof(osVersion) };
    RtlGetVersion(&osVersion);

    LOG_MSG("Running on %i", osVersion.dwBuildNumber);

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
 * Get offset to the process list from the EPROCESS structure, depending on the OS version.
 * Taken from https://github.com/Idov31/Nidhogg/blob/2776908e86c34771d0663e931b1930c64a9d4b15/Nidhogg/WindowsTypes.hpp
 *
 * @return ULONG Offset to Process List.
 */
ULONG
BeGetProcessLinkedListOffset()
{
    RTL_OSVERSIONINFOW osVersion = { sizeof(osVersion) };
    RtlGetVersion(&osVersion);

    LOG_MSG("Running on %i", osVersion.dwBuildNumber);

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
 * Get the base address of a module, such as ntoskrnl.exe
 * https://www.unknowncheats.me/forum/general-programming-and-reversing/427419-getkernelbase.html
 *
 * @returns PVOID address of ntoskrnl.exe
 */
PVOID
BeGetBaseAddrOfModule(WCHAR* moduleName)
{
    PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)(BeGlobals::driverObject)->DriverSection;
    PKLDR_DATA_TABLE_ENTRY first = entry;

    while ((PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != first)
    {
        if (_strcmpi_w(entry->BaseDllName.Buffer, moduleName) == 0)
        {
            return entry->DllBase;
        }
        entry = (PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
    }
    return NULL;
}

/*
 * Gets the address of a function from a module by parsing its EAT
 *
 * @returns PVOID Address of the function, NULL if not resolved
 */
PVOID
BeGetSystemRoutineAddress(const IN ModuleName& moduleName, IN CHAR* functionToResolve)
{
    KAPC_STATE apc;
    PVOID moduleBase = 0;
    bool inWin32kModule = false;

    switch (moduleName)
    {
    case NtOsKrnl:
        moduleBase = BeGlobals::NtOsKrnlAddr;
        break;
    case Win32kBase:
        moduleBase = BeGlobals::Win32kBaseAddr;
        inWin32kModule = true;
        break;
    default:
        LOG_MSG("ERROR: Invalid module\n");
        return NULL;
        break;
    }

    // To read session driver modules, we need to be attached to a process running in a user session // TODO refactor to dedicated function
    // https://www.unknowncheats.me/forum/general-programming-and-reversing/492970-reading-memory-win32kbase-sys.html
    if (inWin32kModule)
    {
        // Attach to winlogon
        PEPROCESS targetProc = 0;
        UNICODE_STRING processName;
        RtlInitUnicodeString(&processName, L"winlogon.exe");

        HANDLE procId = BeGetPidFromProcessName(processName);
        LOG_MSG("Found winlogon PID: %i\n", procId);

        if ((PsLookupProcessByProcessId(procId, &targetProc) != 0)) 
        {
            ObDereferenceObject(targetProc);
            return NULL;
        }

        KeStackAttachProcess(targetProc, &apc);
    }

    // Parse headers and export directory
    PFULL_IMAGE_NT_HEADERS ntHeader = (PFULL_IMAGE_NT_HEADERS)((ULONG_PTR)moduleBase + ((PIMAGE_DOS_HEADER)moduleBase)->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)moduleBase + ntHeader->OptionalHeader.DataDirectory[0].VirtualAddress);

    PULONG addrOfNames = (PULONG)((ULONG_PTR)moduleBase + exportDir->AddressOfNames);
    PULONG addrOfFuncs = (PULONG)((ULONG_PTR)moduleBase + exportDir->AddressOfFunctions);
    PUSHORT addrOfOrdinals = (PUSHORT)((ULONG_PTR)moduleBase + exportDir->AddressOfNameOrdinals);

    // Look through export directory until function is found and return its address
    for (unsigned int i = 0; i < exportDir->NumberOfNames; ++i)
    {
        CHAR* currentFunctionName = (CHAR*)((ULONG_PTR)moduleBase + (ULONG_PTR)addrOfNames[i]);

        if (strcmp(currentFunctionName, functionToResolve) == 0)
        {
            PULONG addr = (PULONG)((ULONG_PTR)moduleBase + (ULONG_PTR)addrOfFuncs[addrOfOrdinals[i]]);

            LOG_MSG("Found: 0x%llx\n", addr);

            if (inWin32kModule)
            {
                KeUnstackDetachProcess(&apc);
            }

            return (PVOID)addr;
        }
    }

    if (inWin32kModule)
    {
        KeUnstackDetachProcess(&apc);
    }

    // Else return null
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
    return (UINT16)(*((PUINT16)BeGetSystemRoutineAddress(NtOsKrnl, "PsIsProtectedProcessLight") + 0x1));
}