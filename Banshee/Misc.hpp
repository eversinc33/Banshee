#pragma once

#include <ntifs.h>
#include "DriverMeta.hpp"

#define DRIVER_LOG_PREFIX "::[Banshee] - "
#ifdef DBG
    #define LOG_MSG(x, ...) DbgPrint((DRIVER_LOG_PREFIX x), __VA_ARGS__)
#else
    #define LOG_MSG(x, ...) 
#endif

/*
 * @brief Check whether a wstring is a nullpointer or contains only null characters
 *
 * @return BOOLEAN True if nullpointer or only null characters
 */
BOOLEAN
BeIsStringNull(_In_ PWCHAR PWchar)
{
    return (PWchar == NULL || *PWchar == '\0');
}

/**
 * @brief Check whether a wstring is null-terminated
 *
 * @return BOOLEAN True if null-terminated.
 */
BOOLEAN
BeIsStringTerminated(_In_ PWCHAR Array, _In_ ULONG ArrayLength)
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
 * @brief Check whether a wstring is null-terminated, not empty and properly aligned
 *
 * @return NTSTATUS depending on if the checks succeed or not
 */
NTSTATUS
BeCheckStringIsAlignedNotEmptyAndTerminated(_In_ PWCHAR TargetString, _In_ ULONG Size)
{
    //
    // Check alignment
    //
    if (Size % sizeof(WCHAR) != 0)
    {
        LOG_MSG("Invalid alignment \r\n");
        return STATUS_INVALID_BUFFER_SIZE;
    }

    if (!TargetString)
    {
        LOG_MSG("Empty buffer \r\n");
        return STATUS_INVALID_PARAMETER;
    }

    LOG_MSG("String received: %ws \r\n", TargetString);

    if (BeIsStringTerminated(TargetString, Size) == FALSE)
    {
        LOG_MSG("Not null terminated! \r\n");
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

/*
 * check if a wide string contains a substring without case sensitivity
 * 
 * @param[in] String string to check
 * @param[in] Pattern pattern to look for
 * 
 * @return PWCHAR NULL if no match is found, otherwise a pointer to the match
 */
PWCHAR
StrStrIW(
    _In_ CONST PWCHAR String, 
    _In_ CONST PWCHAR Pattern
) {
      PWCHAR Pptr, Sptr, Start;

      for (Start = (PWCHAR)String; *Start != NULL; ++Start)
      {
            while (((*Start != NULL) && (RtlUpcaseUnicodeChar(*Start) != RtlUpcaseUnicodeChar(*Pattern))))
            {
                ++Start;
            }

            if (NULL == *Start)
                  return NULL;

            Pptr = (PWCHAR)Pattern;
            Sptr = (PWCHAR)Start;

            while (RtlUpcaseUnicodeChar(*Sptr) == RtlUpcaseUnicodeChar(*Sptr))
            {
                  Sptr++;
                  Pptr++;

                  if (NULL == *Pptr)
                        return (Start);
            }
      }

      return NULL;
}

/*
 * @brief Gets the base name of a full file path
 * Taken from: https://github.com/GetRektBoy724/DCMB/blob/main/DCMB/dcmb.c#L3
 * 
 * @returns PCHAR base name
 */
PCHAR 
GetBaseNameFromFullPath(_In_ PCHAR FullName) 
{
    SIZE_T FullNameLength = strlen(FullName);

    for (SIZE_T I = FullNameLength; I > 0; I--) 
    {
        if (*(FullName + I) == '\\')
        {
            return FullName + I + 1;
        }
    }

    return NULL;
}

/**
 * TODO: description, parameters
 */
NTSTATUS
BeCreateSecurityDescriptor(_Out_ PSECURITY_DESCRIPTOR* sd)
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
 * @brief Sets a named event to a state
 * 
 * @param[in] hEvent Handle to the event
 * @param[in] set signaled state to set
 * 
 * @returns NTSTATUS status code
 */
NTSTATUS
BeSetNamedEvent(
    _In_ HANDLE  hEvent, 
    _In_ BOOLEAN Set
) {
    NTSTATUS Status = STATUS_SUCCESS;

    if (Set)
    {
        Status = BeGlobals::pZwSetEvent(hEvent, NULL);
        if (!NT_SUCCESS(Status))
        {
            LOG_MSG("Failed to set named event: 0x%X\n", Status);
        }
    }
    else
    {
        BeGlobals::pZwResetEvent(hEvent, NULL);
        if (!NT_SUCCESS(Status))
        {
            LOG_MSG("Failed to reset named event: 0x%X\n", Status);
        }
    }

    return Status;
}

/**
 * @brief Wait for an event to be set
 *
 * @param[in] hEvent Handle to the event
 * @returns NTSTATUS status code
 */
NTSTATUS 
BeWaitForEvent(_In_ HANDLE hEvent)
{
    NTSTATUS Status = STATUS_SUCCESS;
    Status = ZwWaitForSingleObject(hEvent, FALSE, NULL);
    return Status;
}

/**
 * @brief Creates a named event
 *
 * @param[out] PhEvent Pointer to a handle to the event
 * @param[in]  EventName name for the event
 * @param[in]  InitialSignaledState the initial state for the event
 * @returns NTSTATUS status code
 */
NTSTATUS 
BeCreateNamedEvent(
    _Out_ PHANDLE         PhEvent, 
    _In_  PUNICODE_STRING EventName, 
    _In_  BOOLEAN         InitialSignaledState
) {
    //
    // Add permissions to all users to our event, so that a lowpriv agent can still access the rootkit
    //
    PSECURITY_DESCRIPTOR Sd  = { 0 };
    OBJECT_ATTRIBUTES    Obj = { 0 };

    BeCreateSecurityDescriptor(&Sd);
    InitializeObjectAttributes(&Obj, EventName, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT | OBJ_KERNEL_HANDLE | OBJ_OPENIF, NULL, Sd);

    NTSTATUS Status = BeGlobals::pZwCreateEvent(PhEvent, EVENT_ALL_ACCESS, &Obj, NotificationEvent, InitialSignaledState);
    if (!NT_SUCCESS(Status))
        DbgPrint("Failed to create named event: 0x%X\n", Status);

    ExFreePool(Sd);
    return Status;
}