#pragma once

#include <ntifs.h>
#include <wdf.h>
#include "Misc.hpp"

// --------------------------------------------------------------------------------------------------------

typedef struct _NON_PAGED_DEBUG_INFO
{
    USHORT Signature;                                                       //0x0
    USHORT Flags;                                                           //0x2
    ULONG Size;                                                             //0x4
    USHORT Machine;                                                         //0x8
    USHORT Characteristics;                                                 //0xa
    ULONG TimeDateStamp;                                                    //0xc
    ULONG CheckSum;                                                         //0x10
    ULONG SizeOfImage;                                                      //0x14
    ULONGLONG ImageBase;                                                    //0x18
} NON_PAGED_DEBUG_INFO;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    PVOID ExceptionTable;
    UINT32 ExceptionTableSize;
    PVOID GpValue;
    NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;
    PVOID DllBase;
    PVOID EntryPoint;
    UINT32 SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    UINT32 Flags;
    UINT16 LoadCount;
    UINT16 SignatureInfo;
    PVOID SectionPointer;
    UINT32 CheckSum;
    UINT32 CoverageSectionSize;
    PVOID CoverageSection;
    PVOID LoadedImports;
    PVOID Spare;
    UINT32 SizeOfImageNotRounded;
    UINT32 TimeDateStamp;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

// Windows versions
#define WIN_1507 10240
#define WIN_1511 10586
#define WIN_1607 14393
#define WIN_1703 15063
#define WIN_1709 16299
#define WIN_1803 17134
#define WIN_1809 17763
#define WIN_1903 18362
#define WIN_1909 18363
#define WIN_2004 19041
#define WIN_20H2 19042
#define WIN_21H1 19043
#define WIN_21H2 19044
#define WIN_22H2 19045
#define WIN_1121H2 22000
#define WIN_1122H2 22621

// Protection Levels - Windows Internals Part 1 - Page 115 (7th english edition)
BYTE PS_PROTECTED_SYSTEM = 0x72; // Geschützt WinSystem
BYTE PS_PROTECTED_WULONGCB = 0x62; // Geschützt WinTcb
BYTE PS_PROTECTED_WULONGCB_LIGHT = 0x61; // PPL WinTcb
BYTE PS_PROTECTED_WINDOWS = 0x52; // Geschützt Windows
BYTE PS_PROTECTED_WINDOWS_LIGHT = 0x51; // PPL Windows
BYTE PS_PROTECTED_LSA_LIGHT = 0x41; // PPL Lsa
BYTE PS_PROTECTED_ANTIMALWARE_LIGHT = 0x31; // PPL Anti - malware
BYTE PS_PROTECTED_AUTHENTICODE = 0x21; // Geschützt Authenticode
BYTE PS_PROTECTED_AUTHENTICODE_LIGHT = 0x11; // PPL Authenticode
BYTE PS_PROTECTED_NONE = 0x00; // Keine Keine

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

    DbgPrint("Running on %i", osVersion.dwBuildNumber);

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

    DbgPrint("Token offset: %i", tokenOffset);
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

    DbgPrint("Running on %i", osVersion.dwBuildNumber);

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
 * Get the base address of ntoskrnl.exe
 * https://www.unknowncheats.me/forum/general-programming-and-reversing/427419-getkernelbase.html
 * 
 * @returns PVOID address of ntoskrnl.exe
 */
PVOID
BeGetKernelBaseAddr(IN PDRIVER_OBJECT DriverObject)
{
    PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
    PKLDR_DATA_TABLE_ENTRY first = entry;

    while ((PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != first)
    {
        if (_strcmpi_w(entry->BaseDllName.Buffer, L"ntoskrnl.exe") == 0)
        {
            return entry->DllBase;
        }
        entry = (PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
    }
    return NULL;
}

/*
 * Gets offset of EPROCESS ProcessProtection dynamically. Shoutout to @never_unsealed and @C5Pider
 *
 * @returns ULONG Offset of EPROCESS ProcessProtection 
 */
ULONG
__BeGetEprocessProcessProtectionOffset()
{
    // TODO
    UNICODE_STRING psIsPpl = RTL_CONSTANT_STRING(L"PsIsProtectedProcessLight");
    // (*((PULONG)MmGetSystemRoutineAddress(&psIsPpl) + XYZ));
    return NULL;
}