#include <windows.h>  

#pragma comment(lib, "Advapi32.lib")

#define HRESULT_FROM_WIN32(x) (x ? ((HRESULT) (((x) & 0x0000FFFF) | (FACILITY_WIN32 << 16) | 0x80000000)) : 0)
#define MAX_GUID_SIZE 39
#define MAX_DATA_LENGTH 65000
#define true 1

//loaddriver
DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(
	_In_opt_      LPCSTR     lpMachineName,
	_In_opt_      LPCSTR     lpDatabaseName,
	_In_          DWORD   dwDesiredAccess
);

DECLSPEC_IMPORT SC_HANDLE WINAPI ADVAPI32$CreateServiceA(
	_In_        SC_HANDLE hSCManager,
	_In_        LPCSTR       lpServiceName,
	_In_opt_    LPCSTR       lpDisplayName,
	_In_        DWORD     dwDesiredAccess,
	_In_        DWORD     dwServiceType,
	_In_        DWORD     dwStartType,
	_In_        DWORD     dwErrorControl,
	_In_opt_    LPCSTR       lpBinaryPathName,
	_In_opt_    LPCSTR       lpLoadOrderGroup,
	_Out_opt_   LPDWORD   lpdwTagId,
	_In_opt_    LPCSTR       lpDependencies,
	_In_opt_    LPCSTR       lpServiceStartName,
	_In_opt_    LPCSTR       lpPassword
);

DECLSPEC_IMPORT BOOL WINAPI ADVAPI32$StartServiceA(
	_In_          SC_HANDLE hService,
	_In_          DWORD     dwNumServiceArgs,
	_In_opt_      LPCSTR* lpServiceArgVectors
);


//main
WINBASEAPI int __cdecl MSVCRT$printf(const char* _Format, ...);
WINBASEAPI int __cdecl MSVCRT$strcmp(const char* str1, const char* str2);
WINBASEAPI int __cdecl MSVCRT$getchar(void); 
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError();


//bofstart + internal_printf + printoutput
WINBASEAPI void* __cdecl MSVCRT$calloc(size_t number, size_t size);
WINBASEAPI int WINAPI MSVCRT$vsnprintf(char* buffer, size_t count, const char* format, va_list arg);
WINBASEAPI void __cdecl MSVCRT$memset(void* dest, int c, size_t count);
WINBASEAPI void* WINAPI MSVCRT$memcpy(void* dest, const void* src, size_t count);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI void __cdecl MSVCRT$free(void* memblock);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);