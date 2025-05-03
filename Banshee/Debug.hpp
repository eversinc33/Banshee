#pragma once

#include <ntddk.h>

#define DRIVER_LOG_PREFIX "::[Banshee] - "
#ifdef DBG
#define LOG_MSG(x, ...) DbgPrint((DRIVER_LOG_PREFIX x), __VA_ARGS__)
#else
#define LOG_MSG(x, ...) 
#endif