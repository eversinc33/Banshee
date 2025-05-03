#include "Vector.hpp"

PVOID __cdecl operator new(SIZE_T size, POOL_TYPE Pool)
{
    return ExAllocatePoolWithTag(Pool, size, DRIVER_TAG);
}

PVOID __cdecl operator new[](SIZE_T size, POOL_TYPE Pool)
{
    return ExAllocatePoolWithTag(Pool, size, DRIVER_TAG);
}

VOID __cdecl operator delete(PVOID ptr, SIZE_T)
{
    ExFreePool(ptr);
}

VOID __cdecl operator delete(PVOID ptr)
{
    ExFreePool(ptr);
}

VOID __cdecl operator delete[](PVOID ptr, SIZE_T)
{
    ExFreePool(ptr);
}

VOID __cdecl operator delete[](PVOID ptr)
{
    ExFreePool(ptr);
}