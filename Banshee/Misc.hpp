#pragma once

#include <ntifs.h>

// TODO: add formatted debug print method with driver prefix

/*
 * Check whether a wstring is a nullpointer or contains only null characters
 *
 * @return BOOLEAN True if nullpointer or only null characters
 */
BOOLEAN
BeIsStringNull(PWCHAR pWchar)
{
    return (pWchar == NULL || *pWchar == '\0');
}

/**
 * Check whether a wstring is null-terminated
 *
 * @return BOOLEAN True if null-terminated.
 */
BOOLEAN
BeIsStringTerminated(PWCHAR Array, ULONG ArrayLength)
{
    BOOLEAN bStringIsTerminated = FALSE;
    USHORT uiIndex = 0;

    while (uiIndex < ArrayLength && bStringIsTerminated == FALSE)
    {
        if (Array[uiIndex] == L'\0')
        {
            bStringIsTerminated = TRUE;
        }
        else
        {
            uiIndex++;
        }
    }
    return bStringIsTerminated;
}

/*
 * Converts a wchar to lowercase
 * 
 * @returns wchar_t wchar in lowercase
 */
__forceinline wchar_t locase_w(wchar_t c)
{
    if ((c >= 'A') && (c <= 'Z'))
        return c + 0x20;
    else
        return c;
}

/*
 * compares two wchars without case sensitivity
 */
int _strcmpi_w(const wchar_t* s1, const wchar_t* s2)
{
    wchar_t c1, c2;

    if (s1 == s2)
        return 0;

    if (s1 == 0)
        return -1;

    if (s2 == 0)
        return 1;

    do {
        c1 = locase_w(*s1);
        c2 = locase_w(*s2);
        s1++;
        s2++;
    } while ((c1 != 0) && (c1 == c2));

    return (int)(c1 - c2);
}