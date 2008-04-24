/*
 * Copyright (C) 2001-2004 The Honeynet Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by The Honeynet Project.
 * 4. The name "The Honeynet Project" may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "sebek.h"
#include "util.h"
#include "antidetection.h"

extern CHAR g_ServiceName[12];
extern ZWOPENKEY s_fnZwOpenKey;
extern UNICODE_STRING g_ImagePath;

/* Find the offset of the process name within the executive process
   block.  We do this by searching for the first occurance of "System"
   in the current process when the device driver is loaded. */

void GetProcessNameOffset()
{
	PEPROCESS curproc = PsGetCurrentProcess();
	ULONG i;
	for(i = 0; i < 3 * PAGE_SIZE; i++ ) {
		if(!strncmp( "System", (PCHAR) curproc + i, strlen("System")))
			gProcessNameOffset = i;
	}
}

/* Copy the process name into the specified buffer.  */

BOOLEAN GetProcessName( PCHAR theName )
{
	PEPROCESS       curproc;
	char            *nameptr;

	if(!theName)
		return FALSE;

	if(gProcessNameOffset) {
		curproc = PsGetCurrentProcess();
		nameptr   = (PCHAR) curproc + gProcessNameOffset;
		strncpy( theName, nameptr, NT_PROCNAMELEN );
		theName[NT_PROCNAMELEN] = 0; /* NULL at end */
		return TRUE;
	}
	return FALSE;
}

NTSTATUS
RegGetSz(
    IN      ULONG  RelativeTo,               
    IN CONST PWSTR  Path,
    IN      PWSTR  ParameterName,
    IN OUT  PUNICODE_STRING ParameterValue
    )
{
    NTSTATUS                  status;
    RTL_QUERY_REGISTRY_TABLE  paramTable[2];

    //
    // sanity check parameters - reject NULL pointers and invalid
    //   UNICODE_STRING field initializations
    //
    if( ( NULL == Path ) || ( NULL == ParameterName ) || ( NULL == ParameterValue ) ) {
        return STATUS_INVALID_PARAMETER;
    }
    if( (ParameterValue->Length != 0) || (ParameterValue->MaximumLength !=0) || (ParameterValue->Buffer != NULL) ) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // set up table entries for call to RtlQueryRegistryValues
    //
    // leave paramTable[1] as all zeros to terminate the table
    //
    // use RtlQueryRegistryValues to do the grunge work
    //
    RtlZeroMemory( paramTable, sizeof(paramTable) );

    paramTable[0].Flags         = RTL_QUERY_REGISTRY_DIRECT;
    paramTable[0].Name          = ParameterName;
    paramTable[0].EntryContext  = ParameterValue;
    paramTable[0].DefaultType   = REG_SZ;
    paramTable[0].DefaultData   = L"";
    paramTable[0].DefaultLength = 0;

    status = RtlQueryRegistryValues( RelativeTo | RTL_REGISTRY_OPTIONAL,
                                     Path,
                                     &paramTable[0],
                                     NULL,
                                     NULL);
       
    if( status != STATUS_SUCCESS ) {
        DBGOUT(("RtlQueryRegistryValues FAILED status=%x\n",status));
				return status;
    }

    //
    // Try to make ParameterValue->Buffer safe to use as a PWSTR parameter. 
    //   Clean up the allocation and fail this request if we are unable to do so.
    //
    if(ParameterValue->Buffer != NULL) {
        if( ParameterValue->MaximumLength >= (ParameterValue->Length + sizeof(WCHAR)) ) {
            (ParameterValue->Buffer)[ ParameterValue->Length / sizeof(WCHAR) ] = UNICODE_NULL;
        } else {

            ExFreePool( ParameterValue->Buffer );
            ParameterValue->Length        = 0;
            ParameterValue->MaximumLength = 0;
            ParameterValue->Buffer        = 0;
            status = STATUS_UNSUCCESSFUL;

        }
    }

    return status;
}

NTSTATUS
RegGetDword(
    IN     ULONG  RelativeTo,               
    IN     PWSTR  Path,
    IN     PWSTR  ParameterName,
    IN OUT PULONG ParameterValue
    )
{
    NTSTATUS                  status;
    RTL_QUERY_REGISTRY_TABLE  paramTable[2];
    ULONG                     defaultValue;

    if( ( NULL == Path ) || ( NULL == ParameterName ) || ( NULL == ParameterValue ) ) {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // set up table entries for call to RtlQueryRegistryValues
    //
    // leave paramTable[1] as all zeros to terminate the table
    //
    // use original value as default value
    //
    // use RtlQueryRegistryValues to do the grunge work
    //
    RtlZeroMemory( paramTable, sizeof(paramTable) );

    defaultValue = *ParameterValue;

    paramTable[0].Flags         = RTL_QUERY_REGISTRY_DIRECT;
    paramTable[0].Name          = ParameterName;
    paramTable[0].EntryContext  = ParameterValue;
    paramTable[0].DefaultType   = REG_DWORD;
    paramTable[0].DefaultData   = &defaultValue;
    paramTable[0].DefaultLength = sizeof(ULONG);

    status = RtlQueryRegistryValues( RelativeTo | RTL_REGISTRY_OPTIONAL,
                                     Path,
                                     &paramTable[0],
                                     NULL,
                                     NULL);
       
    if( status != STATUS_SUCCESS ) {
        DBGOUT(("RtlQueryRegistryValues FAILED w/status=%x\n",status));
    }

    return status;
}

/*
 * Retrieve the full pathname (including files and registry keys) for a
 * given handle. This method is from "Undocumented Windows NT".
 */
BOOLEAN PathFromHandle (HANDLE hKey, PUNICODE_STRING lpszSubKeyVal, PCHAR fullname)
{
	PVOID			pKey = NULL;
	ANSI_STRING		keyname;
	PCHAR			tmpname;
	PUNICODE_STRING		fullUniName;
	ULONG			actualLen;

	if(!fullname)
		return FALSE;

	/* Allocate a temporary buffer */
	tmpname = ExAllocatePool (PagedPool, MAXPATHLEN);
	if (tmpname == NULL)
		/* Not enough memory */
		return FALSE;

	*fullname = *tmpname = '\0';

	/*
	 * Translate the hKey into a pointer to check whether it is a valid
	 * handle.
	 */
	if (NT_SUCCESS (ObReferenceObjectByHandle (hKey, 0, NULL, KernelMode, 
		&pKey, NULL)) && pKey != NULL) {

		fullUniName = ExAllocatePool (PagedPool, MAXPATHLEN * 2 + 
			2 * sizeof(ULONG));
		if (fullUniName == NULL) {
			/* Not enough memory */
			ObDereferenceObject (pKey);
			ExFreePool (tmpname);
			return FALSE;
		}

		fullUniName->MaximumLength = MAXPATHLEN*2;
		if (NT_SUCCESS (ObQueryNameString (pKey, fullUniName, 
			MAXPATHLEN, &actualLen ))) {
			if (NT_SUCCESS (RtlUnicodeStringToAnsiString (
				&keyname, fullUniName, TRUE))) { 
				if(*keyname.Buffer != '\0') {
					if (*keyname.Buffer != '\\')
						strcpy (tmpname, "\\");
					else
						strcpy (tmpname, "");
					strncat (tmpname, keyname.Buffer, 
						min( keyname.Length, 
						MAXPATHLEN - 2 ));
				}
				RtlFreeAnsiString (&keyname);
			}
		}

		ObDereferenceObject (pKey);
		ExFreePool (fullUniName);
	}

	/* Append subkey and value if they are there */
	if (lpszSubKeyVal != NULL) {
		keyname.Buffer = NULL;
		if (NT_SUCCESS (RtlUnicodeStringToAnsiString (&keyname, 
			lpszSubKeyVal, TRUE))) {
			if (*keyname.Buffer != '\0') {
				size_t iLen = MAXPATHLEN - (strlen(tmpname) - 1);
				strcat(tmpname, "\\");
				strncat(tmpname, keyname.Buffer,	min(keyname.Length, iLen));
			}
			RtlFreeAnsiString (&keyname);
		}
	}

	strcpy (fullname, tmpname);
	ExFreePool (tmpname);

return TRUE;
}

/*
 * Here is what we have to do:
 * 
 * We take in time structure that is > January 1, 1970.
 * We create a structure that is the first second of January 1, 1970.
 * Since the From Time is > 1970, to get the number of 100-nanoseconds 
 * since 1970 we just subtract the two dates.
 * we then have to convert the LARGE_INTEGER to a 32bit integer.
 */
void ConvertToSecondsFrom1970(CONST PLARGE_INTEGER pFrom, PULONG pTo, PULONG pMillseconds)
{
	TIME_FIELDS tf1970;
	LARGE_INTEGER t1970, tmp;
#if (_WIN32_WINNT == 0x0500) // WIN2k
	LARGE_INTEGER remainder, divisor;
	divisor.QuadPart = 10000000;
#endif

	if(!pFrom || !pTo)
		return;
	
	tf1970.Year = 1970;
	tf1970.Day = 1;
	tf1970.Hour = 0;
	tf1970.Minute = 0;
	tf1970.Second = 1;
	tf1970.Month = 1;
	tf1970.Milliseconds = 0;

	RtlTimeFieldsToTime(&tf1970, &t1970);
	tmp.QuadPart = pFrom->QuadPart - t1970.QuadPart;
	*pTo = (ULONG)(*((__int64 *) &tmp) / 10000000U);
	if(pMillseconds) {
#if (_WIN32_WINNT == 0x0500) // WIN2k
		RtlLargeIntegerDivide(tmp, divisor, &remainder);
		*pMillseconds = (ULONG)remainder.QuadPart / 1000;
#else
		*pMillseconds = (ULONG)(*((__int64 *) &tmp) % 10000000U) / 1000;
#endif
	}
}

// NOTE: We must used our stored pointers to the REAL
// versions of the Zw* functions otherwise we will protect us from ourselves =)

BOOLEAN RemoveModule(void)
{
	UNICODE_STRING usKeyName, usServiceName;
	ANSI_STRING asServiceName;
	BOOLEAN fRet = TRUE;
	HANDLE hKey;
	OBJECT_ATTRIBUTES objAttr;
	NTSTATUS status;
	IO_STATUS_BLOCK ioStatusBlock;
	UNICODE_STRING usServicesKey;
	UNICODE_STRING usEnumKeyName;

	RtlInitUnicodeString(&usServicesKey, L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Services\\");
	RtlInitUnicodeString(&usEnumKeyName, L"\\Enum");
	RtlInitUnicodeString(&usKeyName, NULL);

	DBGOUT(("ServiceName ANSI: %s", g_ServiceName));
	RtlInitAnsiString(&asServiceName, g_ServiceName);
	status = RtlAnsiStringToUnicodeString(&usServiceName, &asServiceName, TRUE);
	if(!NT_SUCCESS(status)) {
		DBGOUT(("RemoveModule: FAILURE in  RtlAnsiStringToUnicodeString %08x!", status));
		fRet = FALSE;
		goto end;
	}

	DBGOUT(("ServiceName UNICODE: %S", usServiceName.Buffer));
	// Remove our registry entries
	usKeyName.MaximumLength = usServicesKey.Length + usServiceName.Length + usEnumKeyName.Length + sizeof(WCHAR);
	usKeyName.Buffer = ExAllocatePool(NonPagedPool, usKeyName.MaximumLength);
	RtlZeroMemory(usKeyName.Buffer, usKeyName.MaximumLength);
	DBGOUT(("KeyName Length: %d", usKeyName.MaximumLength));

	RtlCopyUnicodeString(&usKeyName, &usServicesKey);
	status = RtlAppendUnicodeStringToString(&usKeyName, &usServiceName);
	if(!NT_SUCCESS(status)) {
		DBGOUT(("RemoveModule: FAILURE in RtlAppendUnicodeStringToString %08x!", status));
		fRet = FALSE;
		goto end;
	}

	status = RtlAppendUnicodeStringToString(&usKeyName, &usEnumKeyName);
	if(!NT_SUCCESS(status)) {
		DBGOUT(("RemoveModule: FAILURE in RtlAppendUnicodeStringToString %08x!", status));
		fRet = FALSE;
		goto end;
	}

	InitializeObjectAttributes(&objAttr, &usKeyName,0,NULL,NULL);

	DBGOUT(("Attempting to delete reg key %S", usKeyName.Buffer));
#ifdef ENABLE_ANTIDETECTION
	status = s_fnZwOpenKey(&hKey, DELETE, &objAttr);
#else
	status = ZwOpenKey(&hKey, DELETE, &objAttr);
#endif
	if(!NT_SUCCESS(status)) {
		DBGOUT(("RemoveModule: FAILURE in ZwOpenKey %08x!", status));
		fRet = FALSE;
		goto end;
	}

	status = ZwDeleteKey(hKey);
	if(!NT_SUCCESS(status)) {
		DBGOUT(("RemoveModule: Unable to ZwDeleteKey %08x!", status));
		fRet = FALSE;
		goto end;
	}

	// Remove our root key entry now
	RtlZeroMemory(usKeyName.Buffer, usKeyName.MaximumLength);
	RtlCopyUnicodeString(&usKeyName, &usServicesKey);
	status = RtlAppendUnicodeStringToString(&usKeyName, &usServiceName);
	if(!NT_SUCCESS(status)) {
		DBGOUT(("RemoveModule: FAILURE in RtlAppendUnicodeStringToString %08x!", status));
		fRet = FALSE;
		goto end;
	}

	InitializeObjectAttributes(&objAttr, &usKeyName,0,NULL,NULL);
	DBGOUT(("Attempting to delete reg key %S", usKeyName.Buffer));
#ifdef ENABLE_ANTIDETECTION
	status = s_fnZwOpenKey(&hKey, DELETE, &objAttr);
#else
	status = ZwOpenKey(&hKey, DELETE, &objAttr);
#endif
	if(!NT_SUCCESS(status)) {
		DBGOUT(("RemoveModule: FAILURE in ZwOpenKey %08x!", status));
		fRet = FALSE;
		goto end;
	}

	status = ZwDeleteKey(hKey);
	if(!NT_SUCCESS(status)) {
		DBGOUT(("RemoveModule: Unable to ZwDeleteKey %08x!", status));
		fRet = FALSE;
		goto end;
	}

	if(!_wcsnicmp(g_ImagePath.Buffer, L"system32", 8)) {
		UNICODE_STRING usSysRoot;
		RtlInitUnicodeString(&usSysRoot, L"\\SystemRoot\\");
		// Prepend \SystemRoot\ to the string
		ExFreePool(usKeyName.Buffer);
		usKeyName.MaximumLength = usSysRoot.Length + g_ImagePath.Length + sizeof(WCHAR);
		usKeyName.Buffer = ExAllocatePool(NonPagedPool, usKeyName.MaximumLength);
		RtlZeroMemory(usKeyName.Buffer, usKeyName.MaximumLength);
		RtlCopyUnicodeString(&usKeyName, &usSysRoot);
		status = RtlAppendUnicodeStringToString(&usKeyName, &g_ImagePath);
		if(!NT_SUCCESS(status)) {
			DBGOUT(("RemoveModule: FAILURE in RtlAppendUnicodeStringToString %08x!", status));
			fRet = FALSE;
			goto end;
		}

		InitializeObjectAttributes(&objAttr, &usKeyName,  OBJ_CASE_INSENSITIVE, NULL, NULL);
	} else {
		// Use whatever was there
		InitializeObjectAttributes(&objAttr, &g_ImagePath,  OBJ_CASE_INSENSITIVE, NULL, NULL);
	}
	// Remove our file
	DBGOUT(("Removing file %S", objAttr.ObjectName->Buffer));

	status = ZwCreateFile(&hKey, DELETE, &objAttr, &ioStatusBlock, (PLARGE_INTEGER)NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, FILE_DELETE_ON_CLOSE, 0, 0);
	if(!NT_SUCCESS(status)) {
		DBGOUT(("RemoveModule: Unable to ZwCreateFile %08x!", status));
		fRet = FALSE;
		goto end;
	}

	status = ZwClose(hKey);
	if(!NT_SUCCESS(status)) {
		DBGOUT(("RemoveModule: Unable to ZwClose File %08x!", status));
		fRet = FALSE;
		goto end;
	}

end:
	RtlFreeUnicodeString(&usServiceName);
	ExFreePool(usKeyName.Buffer);
	return fRet;
}

// Largely based off of undelete.c from sysinternals
BOOLEAN GetUserSIDFromProcess(EPROCESS *pProcess, UNICODE_STRING *pusSID)
{
	NTSTATUS status;
	ULONG RetLen;
	HANDLE hToken;
	PTOKEN_USER tokenInfoBuffer;
	PACCESS_TOKEN Token;

	Token = PsReferencePrimaryToken(pProcess);

	status = ObOpenObjectByPointer(Token, 0, NULL, TOKEN_QUERY, NULL, KernelMode, &hToken);
	ObDereferenceObject(Token);

	if(!NT_SUCCESS(status))
		return FALSE;

	// Get the size of the sid.
	status = ZwQueryInformationToken(hToken, TokenUser, NULL, 0, &RetLen);
	if(status != STATUS_BUFFER_TOO_SMALL) {
    ZwClose(hToken);
    return FALSE;
  }

	tokenInfoBuffer = (PTOKEN_USER)ExAllocatePool(NonPagedPool, RetLen);
	if(tokenInfoBuffer)
      status = ZwQueryInformationToken(hToken, TokenUser, tokenInfoBuffer, RetLen, &RetLen);
 
  if(!NT_SUCCESS(status) || !tokenInfoBuffer ) {
    DBGOUT(("Error getting token information: %x\n", status));
    if(tokenInfoBuffer)
			ExFreePool(tokenInfoBuffer);
    ZwClose(hToken);
    return FALSE;
  }
  ZwClose(hToken);

  status = RtlConvertSidToUnicodeString(pusSID, tokenInfoBuffer->User.Sid, FALSE);
  ExFreePool(tokenInfoBuffer);

  if(!NT_SUCCESS(status)) {
    DBGOUT(("Unable to convert SID to UNICODE: %x\n", status ));
    return FALSE;
  }

	return TRUE;
}
