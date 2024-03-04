#pragma once
#include <ntifs.h>
#include <wdf.h>

#define DRIVER_TAG 'ehsB'

UNICODE_STRING usDriverName = RTL_CONSTANT_STRING(L"\\Driver\\Banshee");
UNICODE_STRING usDeviceName = RTL_CONSTANT_STRING(L"\\Device\\Banshee");
UNICODE_STRING usDosDeviceName = RTL_CONSTANT_STRING(L"\\DosDevices\\Banshee");