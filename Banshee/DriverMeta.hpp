#pragma once
#include <ntifs.h>
#include <wdf.h>

// Bshe
#define DRIVER_TAG 'ehsB'

// Device names
UNICODE_STRING usDriverName = RTL_CONSTANT_STRING(L"\\Device\\Banshee");
UNICODE_STRING usDosDeviceName = RTL_CONSTANT_STRING(L"\\DosDevices\\Banshee");
