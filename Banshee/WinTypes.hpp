#pragma once

#include <ntifs.h>
#include <wdf.h>
#include "Misc.hpp"

#define ASM_CALL_NEAR 0xE8
#define ASM_JMP_NEAR 0xE9
#define ASM_LEA_R13_BYTE1 0x4C
#define ASM_LEA_R13_BYTE2 0x8D
#define ASM_LEA_RCX_BYTE1 0x48
#define ASM_LEA_RCX_BYTE2 0x8D

typedef UCHAR BYTE;
typedef USHORT WORD;
typedef ULONG DWORD;

enum CALLBACK_TYPE {
	CallbackTypeNone = 0,
    CreateProcessNotifyRoutine = 1,
    CreateThreadNotifyRoutine = 2
};

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

// reactos kernel callback structs

typedef struct _EX_CALLBACK_ROUTINE_BLOCK
{
    EX_RUNDOWN_REF RundownProtect;
    PEX_CALLBACK_FUNCTION Function;
    PVOID Context;
} EX_CALLBACK_ROUTINE_BLOCK, * PEX_CALLBACK_ROUTINE_BLOCK;

// PE headers

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	WORD   e_magic;                     // Magic number
	WORD   e_cblp;                      // Bytes on last page of file
	WORD   e_cp;                        // Pages file
	WORD   e_crlc;                      // Relocations
	WORD   e_cparhdr;                   // Size of header paragraphs
	WORD   e_minalloc;                  // Minimum extra paragraphs needed
	WORD   e_maxalloc;                  // Maximum extra paragraphs needed
	WORD   e_ss;                        // Initial (relative) SS value
	WORD   e_sp;                        // Initial SP value
	WORD   e_csum;                      // Checksum
	WORD   e_ip;                        // Initial IP value
	WORD   e_cs;                        // Initial (relative) CS value
	WORD   e_lfarlc;                    // File address of relocation table
	WORD   e_ovno;                      // Overlay number
	WORD   e_res[4];                    // Reserved words
	WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
	WORD   e_oeminfo;                   // OEM information; e_oemid specific
	WORD   e_res2[10];                  // Reserved words
	LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	ULONG   VirtualAddress;
	ULONG   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_EXPORT_DIRECTORY {
	DWORD   Characteristics;
	DWORD   TimeDateStamp;
	WORD    MajorVersion;
	WORD    MinorVersion;
	DWORD   Name;
	DWORD   Base;
	DWORD   NumberOfFunctions;
	DWORD   NumberOfNames;
	DWORD   AddressOfFunctions;     // RVA from base of image
	DWORD   AddressOfNames;         // RVA from base of image
	DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_OPTIONAL_HEADER {
	WORD        Magic;
	BYTE        MajorLinkerVersion;
	BYTE        MinorLinkerVersion;
	DWORD       SizeOfCode;
	DWORD       SizeOfInitializedData;
	DWORD       SizeOfUninitializedData;
	DWORD       AddressOfEntryPoint;
	DWORD       BaseOfCode;
	ULONGLONG   ImageBase;
	DWORD       SectionAlignment;
	DWORD       FileAlignment;
	WORD        MajorOperatingSystemVersion;
	WORD        MinorOperatingSystemVersion;
	WORD        MajorImageVersion;
	WORD        MinorImageVersion;
	WORD        MajorSubsystemVersion;
	WORD        MinorSubsystemVersion;
	DWORD       Win32VersionValue;
	DWORD       SizeOfImage;
	DWORD       SizeOfHeaders;
	DWORD       CheckSum;
	WORD        Subsystem;
	WORD        DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	DWORD       LoaderFlags;
	DWORD       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, * PIMAGE_OPTIONAL_HEADER;

typedef struct _FULL_IMAGE_NT_HEADERS {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
} FULL_IMAGE_NT_HEADERS, * PFULL_IMAGE_NT_HEADERS;

typedef struct _IMAGE_SECTION_HEADER
{
	UCHAR  Name[8];
	union
	{
		ULONG PhysicalAddress;
		ULONG VirtualSize;
	} Misc;
	ULONG VirtualAddress;
	ULONG SizeOfRawData;
	ULONG PointerToRawData;
	ULONG PointerToRelocations;
	ULONG PointerToLinenumbers;
	USHORT  NumberOfRelocations;
	USHORT  NumberOfLinenumbers;
	ULONG Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45,
	SystemCodeIntegrityInformation = 103,
	SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;

// TODO: is this portable?
typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER Reserved[3];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	ULONG BasePriority;
	HANDLE ProcessId;
	HANDLE InheritedFromProcessId;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;
