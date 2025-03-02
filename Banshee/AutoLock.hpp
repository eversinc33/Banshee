#pragma once

// From Pavel Yosifovich: Windows Kernel Programming

class FastMutex
{
private:
    FAST_MUTEX _mutex;

public:
    void Init()
    {
        ExInitializeFastMutex(&_mutex);
    }

    void Lock()
    {
        ExAcquireFastMutex(&_mutex);
    }

    void Unlock()
    {
        ExReleaseFastMutex(&_mutex);
    }
};

template<typename TLock>
struct AutoLock {
    AutoLock(TLock& lock) 
        : _lock(lock) 
    {
        _lock.Lock();
    }

    ~AutoLock() 
    {
        _lock.Unlock();
    }

private:
    TLock& _lock;
};