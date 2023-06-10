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
 * compares two wchar strings without case sensitivity
 * 
 * @param s1 first string
 * @param s2 second string 
 * @return INT 0 if both string are qual
 */
INT
_strcmpi_w(const wchar_t* s1, const wchar_t* s2)
{
    WCHAR c1, c2;

    if (s1 == s2)
        return 0;

    if (s1 == 0)
        return -1;

    if (s2 == 0)
        return 1;

    do {
        c1 = RtlUpcaseUnicodeChar(*s1);
        c2 = RtlUpcaseUnicodeChar(*s2);
        s1++;
        s2++;
    } while ((c1 != 0) && (c1 == c2));

    return (INT)(c1 - c2);
}

/*
 * check if a wide string contains a substring without case sensitivity
 * 
 * @param String string to check
 * @param Pattern pattern to look for
 * @return PWCHAR NULL if no match is found, otherwise a pointer to the match
 */
PWCHAR
StrStrIW(const PWCHAR String, const PWCHAR Pattern)
{
      PWCHAR pptr, sptr, start;

      for (start = (PWCHAR)String; *start != NULL; ++start)
      {
            while (((*start!=NUL) && (RtlUpcaseUnicodeChar(*start) 
                    != RtlUpcaseUnicodeChar(*Pattern))))
            {
                ++start;
            }

            if (NULL == *start)
                  return NULL;

            pptr = (PWCHAR)Pattern;
            sptr = (PWCHAR)start;

            while (RtlUpcaseUnicodeChar(*sptr) == RtlUpcaseUnicodeChar(*pptr))
            {
                  sptr++;
                  pptr++;

                  if (NULL == *pptr)
                        return (start);
            }
      }

      return NULL;
}