#pragma once

#include <ntifs.h>
#include <wdf.h>

#include "DriverMeta.hpp"

// https://github.com/gauraVsehgaL/cppkernel/blob/master/vector.hpp

PVOID __cdecl operator new(SIZE_T size, POOL_TYPE Pool)
{
    return ExAllocatePoolWithTag(Pool, size, DRIVER_TAG);
}

PVOID __cdecl operator new[](SIZE_T size, POOL_TYPE Pool)
{
    return ExAllocatePoolWithTag(Pool, size, DRIVER_TAG);
}

//    Placement new
inline PVOID operator new(SIZE_T, PVOID where)
{
    return where;
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

// TEMPLATE CLASS remove_reference
template <class _Ty>
struct remove_reference
{  // remove reference
    typedef _Ty type;
};

template <class _Ty>
struct remove_reference<_Ty&>
{  // remove reference
    typedef _Ty type;
};

template <class _Ty>
struct remove_reference<_Ty&&>
{  // remove rvalue reference
    typedef _Ty type;
};

template <typename T>
typename remove_reference<T>::type&& move(T&& arg)
{
    return static_cast<typename remove_reference<T>::type&&>(arg);
}

// TEMPLATE FUNCTION forward
template <class _Ty>
inline constexpr _Ty&& forward(typename remove_reference<_Ty>::type& _Arg)
{  // forward an lvalue as either an lvalue or an rvalue
    return (static_cast<_Ty&&>(_Arg));
}

template <class _Ty>
inline constexpr _Ty&& forward(typename remove_reference<_Ty>::type&& _Arg)
{  // forward an rvalue as an rvalue
    return (static_cast<_Ty&&>(_Arg));
}

namespace ktd
{
template <typename T, POOL_TYPE PoolType>
class vector
{
   public:
    unsigned long Tag = DRIVER_TAG;

    vector() : ptr(nullptr), Capacity(0), NumberOfElements(0)
    {
    }

    vector(SIZE_T InitialNumberOfElements) : ptr(nullptr), Capacity(0), NumberOfElements(0)
    {
        reserve(InitialNumberOfElements);
        NumberOfElements = InitialNumberOfElements;
        for (auto i = 0UL; i < NumberOfElements; i++) new (ptr + i) T();
    }

    vector(SIZE_T InitialNumberOfElements, T val) : vector(InitialNumberOfElements)
    {
        reserve(InitialNumberOfElements);
        NumberOfElements = InitialNumberOfElements;
        for (auto i = 0UL; i < NumberOfElements; i++) new (ptr + i) T(val);
    }

    vector(const vector<T, PoolType>& other) : vector()
    {
        reserve(other.Capacity);
        NumberOfElements = other.NumberOfElements;
        for (auto i = 0UL; i < NumberOfElements; i++) new (ptr + i) T(other.ptr[i]);
    }

    vector(vector<T, PoolType>&& other) : Capacity(other.Capacity), NumberOfElements(other.NumberOfElements)
    {
        this->ptr = other.ptr;
        other.ptr = nullptr;
    }

    vector<T, PoolType>& operator=(vector<T, PoolType>&& other)
    {
        if (this != &other)
        {
            this->Capacity = other.Capacity;
            this->NumberOfElements = other.NumberOfElements;
            this->ptr = other.ptr;
            other.ptr = nullptr;
        }

        return *this;
    }

    vector<T, PoolType>& operator=(const vector<T, PoolType>& other)
    {
        if (this != &other)
        {
            if (this->Capacity < other.Capacity)
            {
                this->Capacity = other.Capacity;
                auto OrigPtr = this->ptr;
                this->ptr = allocate(Capacity);
                destroy(OrigPtr, this->NumberOfElements);
                deallocate(OrigPtr);
            }

            this->NumberOfElements = other.NumberOfElements;

            for (auto i = 0UL; i < NumberOfElements; i++) ptr[i] = other.ptr[i];
        }

        return *this;
    }

    ~vector()
    {
        // explicitly call destructors if required.
        if (!ptr)
            return;

        for (auto i = 0UL; i < NumberOfElements; i++) ptr[i].~T();

        deallocate(ptr);
    }

    VOID reserve(SIZE_T NewCapacity)
    {
        if (NewCapacity <= Capacity || NewCapacity == 0)
            return;

        auto origptr = ptr;
        ptr = allocate(NewCapacity);

        for (auto i = 0UL; i < NumberOfElements; i++) new (ptr + i) T(origptr[i]);

        Capacity = NewCapacity;

        if (origptr)
        {
            for (auto i = 0UL; i < NumberOfElements; i++) origptr[i].~T();

            deallocate(origptr);
        }
    }

    VOID push_back(const T& val)
    {
        auto NewCapacity = Capacity;
        if (NumberOfElements + 1 > Capacity)
        {
            // re allocate.
            if (Capacity == 0)
                NewCapacity = 1;

            NewCapacity *= 2;

            reserve(NewCapacity);
        }

        new (ptr + NumberOfElements) T(val);
        NumberOfElements++;
    }

    VOID push_back(T&& val)
    {
        auto NewCapacity = Capacity;
        if (NumberOfElements + 1 > Capacity)
        {
            // re allocate.
            if (Capacity == 0)
                NewCapacity = 1;

            NewCapacity *= 2;

            reserve(NewCapacity);
        }

        new (ptr + NumberOfElements) T(move(val));
        NumberOfElements++;
    }

    template <class... Args>
    T& emplace_back(Args&&... args)
    {
        auto NewCapacity = Capacity;
        if (NumberOfElements + 1 > Capacity)
        {
            // re allocate.
            if (Capacity == 0)
                NewCapacity = 1;

            NewCapacity *= 2;

            reserve(NewCapacity);
        }

        new (ptr + NumberOfElements) T(forward<Args>(args)...);

        return ptr[NumberOfElements++];
    }

    SIZE_T size()
    {
        return this->NumberOfElements;
    }

    T& operator[](SIZE_T index)
    {
        return ptr[index];
    }

    VOID Clear()
    {
        destroy(ptr, NumberOfElements);
        NumberOfElements = 0;
    }

   private:
    T*     ptr;
    SIZE_T Capacity;
    SIZE_T NumberOfElements;

    T* allocate(SIZE_T NewCapacity)
    {
        return static_cast<T*>(ExAllocatePoolWithTag(PoolType, sizeof(T) * NewCapacity, Tag));
    }

    VOID destroy(T* mem, SIZE_T NumElems)
    {
        if (!mem)
            return;

        for (auto i = 0UL; i < NumElems; i++) mem[i].~T();
    }

    VOID deallocate(T* mem)
    {
        if (mem)
            ExFreePool(mem);
    }
};
}  // namespace ktd