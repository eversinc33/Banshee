#pragma once

#include <ntifs.h>
#include "DriverMeta.hpp"

#define DRIVER_LOG_PREFIX "::[Banshee] - "
#define LOG_MSG(x, ...) DbgPrintEx(0, 0, (DRIVER_LOG_PREFIX x), __VA_ARGS__)

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

/**
 * Check whether a wstring is null-terminated, not empty and properly aligned
 *
 * @return NTSTATUS depending on if the checks succeed or not
 */
NTSTATUS
BeCheckStringIsAlignedNotEmptyAndTerminated(PWCHAR targetString, ULONG dwSize)
{
    // Check alignment
    if (dwSize % sizeof(WCHAR) != 0)
    {
        LOG_MSG("Invalid alignment \r\n");
        return STATUS_INVALID_BUFFER_SIZE;
    }

    if (!targetString)
    {
        LOG_MSG("Empty buffer \r\n");
        return STATUS_INVALID_PARAMETER;
    }

    LOG_MSG("String received: %ws \r\n", targetString);

    if (BeIsStringTerminated(targetString, dwSize) == FALSE)
    {
        LOG_MSG("Not null terminated! \r\n");
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
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
            while (((*start!=NULL) && (RtlUpcaseUnicodeChar(*start) != RtlUpcaseUnicodeChar(*Pattern))))
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

/*
 * Gets the base name of a full file path
 * Taken from: https://github.com/GetRektBoy724/DCMB/blob/main/DCMB/dcmb.c#L3
 * 
 * @returns PCHAR base name
 */
PCHAR 
GetBaseNameFromFullPath(PCHAR FullName) 
{
    SIZE_T FullNameLength = strlen(FullName);

    for (SIZE_T i = FullNameLength; i > 0; i--) 
    {
        if (*(FullName + i) == '\\') 
        {
            return FullName + i + 1;
        }
    }

    return NULL;
}

/**
 * TODO: description, parameters
 */
NTSTATUS
BeCreateSecurityDescriptor(OUT PSECURITY_DESCRIPTOR* sd)
{
    NTSTATUS NtStatus = STATUS_SUCCESS;

    // Create the DACL
    /*
     * Figured out that since we want full access to anyone, we can also just add a 0 ACL ... :)
     */
    /*
    ULONG daclSize = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG) + RtlLengthSid(SeExports->SeAuthenticatedUsersSid);
    PACL Dacl = (PACL)ExAllocatePoolWithTag(NonPagedPool, daclSize, DRIVER_TAG);
    if (!Dacl)
    {
        return STATUS_UNSUCCESSFUL;
    }


    NtStatus = RtlCreateAcl(Dacl, daclSize, ACL_REVISION);
    if (!NT_SUCCESS(NtStatus))
    {
        ExFreePool(Dacl);
        return NtStatus;
    }

    NtStatus = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, SECTION_ALL_ACCESS, SeExports->SeAuthenticatedUsersSid);
    if (!NT_SUCCESS(NtStatus))
    {
        ExFreePool(Dacl);
        return NtStatus;
    }
    */

    // Create the security descriptor
    *sd = (PSECURITY_DESCRIPTOR)ExAllocatePoolWithTag(NonPagedPool, SECURITY_DESCRIPTOR_MIN_LENGTH, DRIVER_TAG); // TODO: FREE
    if (!*sd)
    {
        ExFreePool(*sd);
        // ExFreePool(Dacl);
        return STATUS_UNSUCCESSFUL;
    }

    NtStatus = RtlCreateSecurityDescriptor(*sd, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(NtStatus))
    {
        ExFreePool(sd);
        // ExFreePool(Dacl);
        return NtStatus;
    }

    NtStatus = RtlSetDaclSecurityDescriptor(*sd, TRUE, 0, FALSE); // 0 = Dacl
    if (!NT_SUCCESS(NtStatus))
    {
        LOG_MSG("Failed to set DACL in security descriptor\n");
        ExFreePool(*sd);
        // ExFreePool(Dacl);
        return NtStatus;
    }

    return NtStatus;
}

/**
 * Sets a named event to a state
 * 
 * @param hEvent Handle to the event
 * @param set signaled state to set
 * @returns NTSTATUS status code
 */
NTSTATUS
BeSetNamedEvent(HANDLE hEvent, BOOLEAN set)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (set)
    {
        status = BeGlobals::pZwSetEvent(hEvent, NULL);
        if (!NT_SUCCESS(status))
        {
            LOG_MSG("Failed to set named event: 0x%X\n", status);
        }
    }
    else
    {
        BeGlobals::pZwResetEvent(hEvent, NULL);
        if (!NT_SUCCESS(status))
        {
            LOG_MSG("Failed to reset named event: 0x%X\n", status);
        }
    }

    return status;
}

/**
 * Wait for an event to be set
 *
 * @param hEvent Handle to the event
 * @returns NTSTATUS status code
 */
NTSTATUS 
BeWaitForEvent(HANDLE hEvent)
{
    NTSTATUS status = STATUS_SUCCESS;
    status = ZwWaitForSingleObject(hEvent, FALSE, NULL);
    return status;
}

/**
 * Creates a named event
 *
 * @param phEvent Pointer to a handle to the event
 * @param EventName name for the event
 * @param initialSignaledState the initial state for the event
 * @returns NTSTATUS status code
 */
NTSTATUS 
BeCreateNamedEvent(PHANDLE phEvent, PUNICODE_STRING EventName, BOOLEAN initialSignaledState)
{
    NTSTATUS status;

    // Add permissions to all users to our event, so that a lowpriv agent can still access the rootkit
    PSECURITY_DESCRIPTOR sd = { 0 };
    BeCreateSecurityDescriptor(&sd);
    OBJECT_ATTRIBUTES objAttributes;
    InitializeObjectAttributes(&objAttributes, EventName, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT | OBJ_KERNEL_HANDLE | OBJ_OPENIF, NULL, sd);

    status = ZwCreateEvent(phEvent, EVENT_ALL_ACCESS, &objAttributes, NotificationEvent, initialSignaledState);
    if (!NT_SUCCESS(status)) 
    {
        DbgPrint("Failed to create named event: 0x%X\n", status);
    }

    ExFreePool(sd);
    return status;
}