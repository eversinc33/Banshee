#include "Misc.hpp"
#include "Debug.hpp"
#include "Globals.hpp"

/*
 * @brief Checks whether a wide string is null or contains only null characters.
 *
 * @param[in] PWchar Pointer to a wide string.
 *
 * @return BOOLEAN True if null or only null characters, otherwise false.
 */
BOOLEAN
BeIsStringNull(
    _In_ PWCHAR pWchar
)
{
    return (pWchar == NULL || *pWchar == '\0');
}

/*
 * @brief Checks whether a wide string is null-terminated.
 *
 * @param[in] Array Pointer to a wide string.
 * @param[in] ArrayLength Length of the string.
 *
 * @return BOOLEAN True if null-terminated, otherwise false.
 */
BOOLEAN
BeIsStringTerminated(
    _In_ PWCHAR array,
    _In_ ULONG arrayLength
)
{
    BOOLEAN bStringIsTerminated = FALSE;
    USHORT index = 0;

    while (index < arrayLength && bStringIsTerminated == FALSE)
    {
        if (array[index] == L'\0')
        {
            bStringIsTerminated = TRUE;
        }
        else
        {
            index++;
        }
    }
    return bStringIsTerminated;
}

/*
 * @brief Checks whether a wide string is null-terminated, not empty, and properly aligned.
 *
 * @param[in] TargetString The string to check.
 * @param[in] Size The size of the string buffer.
 *
 * @return NTSTATUS STATUS_SUCCESS if valid, otherwise an error code.
 */
NTSTATUS
BeCheckStringIsAlignedNotEmptyAndTerminated(
    _In_ PWCHAR targetString,
    _In_ ULONG size
)
{
    //
    // Check alignment
    //
    if (size % sizeof(WCHAR) != 0)
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

    if (BeIsStringTerminated(targetString, size) == FALSE)
    {
        LOG_MSG("Not null terminated! \r\n");
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

/*
 * @brief Performs a case-insensitive substring search in a wide string.
 *
 * @param[in] String The string to search in.
 * @param[in] Pattern The pattern to search for.
 *
 * @return PWCHAR Pointer to the match if found, otherwise NULL.
 */
PWCHAR
StrStrIW(
    _In_ CONST PWCHAR string,
    _In_ CONST PWCHAR pattern
) {
    PWCHAR pptr, sptr, start;

    for (start = (PWCHAR)string; *start != NULL; ++start)
    {
        while (((*start != NULL) && (RtlUpcaseUnicodeChar(*start) != RtlUpcaseUnicodeChar(*pattern))))
        {
            ++start;
        }

        if (NULL == *start)
            return NULL;

        pptr = (PWCHAR)pattern;
        sptr = (PWCHAR)start;

        while (RtlUpcaseUnicodeChar(*sptr) == RtlUpcaseUnicodeChar(*sptr))
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
 * @brief Extracts the base name from a full file path.
 * Taken from: https://github.com/GetRektBoy724/DCMB/blob/main/DCMB/dcmb.c#L3
 *
 * @param[in] FullName Full file path.
 *
 * @return PCHAR Pointer to the base name within the string.
 */
PCHAR
GetBaseNameFromFullPath(
    _In_ PCHAR fullName
)
{
    SIZE_T fullNameLength = strlen(fullName);

    for (SIZE_T I = fullNameLength; I > 0; I--)
    {
        if (*(fullName + I) == '\\')
        {
            return fullName + I + 1;
        }
    }

    return NULL;
}

/*
 * @brief Creates a security descriptor with full access to all users.
 *
 * @param[out] Sd Pointer to the created security descriptor.
 *
 * @return NTSTATUS STATUS_SUCCESS if successful, otherwise an error code.
 */
NTSTATUS
BeCreateSecurityDescriptor(
    _Out_ PSECURITY_DESCRIPTOR* sd
)
{
    NTSTATUS status = STATUS_SUCCESS;

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

    status = RtlCreateSecurityDescriptor(*sd, SECURITY_DESCRIPTOR_REVISION);
    if (!NT_SUCCESS(status))
    {
        ExFreePool(sd);
        // ExFreePool(Dacl);
        return status;
    }

    status = RtlSetDaclSecurityDescriptor(*sd, TRUE, 0, FALSE); // 0 = Dacl
    if (!NT_SUCCESS(status))
    {
        LOG_MSG("Failed to set DACL in security descriptor\n");
        ExFreePool(*sd);
        // ExFreePool(Dacl);
        return status;
    }

    return status;
}

/*
 * @brief Sets a named event to a specified state.
 *
 * @param[in] hEvent Handle to the event.
 * @param[in] Set TRUE to signal the event, FALSE to reset it.
 *
 * @return NTSTATUS STATUS_SUCCESS if successful, otherwise an error code.
 */
NTSTATUS
BeSetNamedEvent(
    _In_ HANDLE  hEvent,
    _In_ BOOLEAN set
) {
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

/*
 * @brief Waits for an event to be signaled.
 *
 * @param[in] hEvent Handle to the event.
 *
 * @return NTSTATUS STATUS_SUCCESS if successful, otherwise an error code.
 */
NTSTATUS
BeWaitForEvent(
    _In_ HANDLE hEvent
)
{
    NTSTATUS Status = STATUS_SUCCESS;
    Status = ZwWaitForSingleObject(hEvent, FALSE, NULL);
    return Status;
}

/*
 * @brief Creates a named event with a specified initial state.
 *
 * @param[out] PhEvent Pointer to a handle for the created event.
 * @param[in] EventName Name of the event.
 * @param[in] InitialSignaledState Initial state of the event (signaled or non-signaled).
 *
 * @return NTSTATUS STATUS_SUCCESS if successful, otherwise an error code.
 */
NTSTATUS
BeCreateNamedEvent(
    _Out_ PHANDLE         phEvent,
    _In_  PUNICODE_STRING eventName,
    _In_  BOOLEAN         initialSignaledState
) {
    //
    // Add permissions to all users to our event, so that a lowpriv agent can still access the rootkit
    //
    PSECURITY_DESCRIPTOR sd = { 0 };
    OBJECT_ATTRIBUTES    oa = { 0 };

    BeCreateSecurityDescriptor(&sd);
    InitializeObjectAttributes(&oa, eventName, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT | OBJ_KERNEL_HANDLE | OBJ_OPENIF, NULL, sd);

    NTSTATUS Status = BeGlobals::pZwCreateEvent(phEvent, EVENT_ALL_ACCESS, &oa, NotificationEvent, initialSignaledState);
    if (!NT_SUCCESS(Status))
        DbgPrint("Failed to create named event: 0x%X\n", Status);

    ExFreePool(sd);
    return Status;
}