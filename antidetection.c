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

#include "antidetection.h"
#include "nt.h"
#include <ntdef.h>
#include "sebek.h"
#include "util.h"
#include "exports.h"

extern CHAR g_DriverName[12];
extern UINT g_uiDriverNameLen;

extern CHAR g_ServiceName[12];
extern UINT g_uiServiceNameLen;

UNICODE_STRING g_wConfigProcName;

#define PSLOADEDMODULE_OFFSET 0x14

/*
 * Extract the file name and its length from an entry returned by the
 * ZwQueryDirectoryFile function.
 */
BOOLEAN
NameFromFileInfo(
	PVOID pvRecord,
	FILE_INFORMATION_CLASS InfoClass,
	PWCHAR *ppName,
	PULONG pulNameLen
)
{
	if(!ppName || !pulNameLen || !pvRecord)
		return FALSE;

	*ppName = NULL;
	*pulNameLen = 0UL;

	//lint -e788
	switch (InfoClass) {
		case FileDirectoryInformation:
			*pulNameLen = ((PFILE_DIRECTORY_INFORMATION)pvRecord)->FileNameLength;
			*ppName = ((PFILE_DIRECTORY_INFORMATION)pvRecord)->FileName;
			break;
		case FileFullDirectoryInformation:
			*pulNameLen = ((PFILE_FULL_DIR_INFORMATION)pvRecord)->FileNameLength;
			*ppName = ((PFILE_FULL_DIR_INFORMATION)pvRecord)->FileName;
			break;
		case FileBothDirectoryInformation:
			*pulNameLen = ((PFILE_BOTH_DIR_INFORMATION)pvRecord)->FileNameLength;
			*ppName = ((PFILE_BOTH_DIR_INFORMATION)pvRecord)->FileName;
			break;
		case FileNameInformation:
			*pulNameLen = ((PFILE_NAMES_INFORMATION)pvRecord)->FileNameLength;
			*ppName = ((PFILE_NAMES_INFORMATION)pvRecord)->FileName;
			break;
		default:
			DBGOUT(("NameFromFileInfo() unknown information class %d", InfoClass));
			return FALSE;
	}

	return TRUE;
}

BOOLEAN ShouldHideReg(PCHAR szName)
{
	char *p = NULL;

	p = _strrchr (szName, '\\');
	if(p)
		p++;
	else
		p = szName;

	if(!_strnicmp(g_ServiceName, p, g_uiServiceNameLen))
		return TRUE;
	else
		return FALSE;
}

/*
 * Should we hide this file from the file list?
 */
BOOLEAN
ShouldHideFile(
	PCHAR szFileName
)
{
	char *p = NULL;

	p = _strrchr (szFileName, '\\');
	if(p)
		p++;
	else
		p = szFileName;

	//DBGOUT((" ShouldHideFile: %s", szFileName));
	if(!_strnicmp(g_DriverName, p, g_uiDriverNameLen))
		return TRUE;
	else
		return FALSE;
}

/*
 * Step through the results of ZwQueryDirectoryFile, removing files we want
 * to hide from the listing.
 */
NTSTATUS
ProcessDirEntries(
	PVOID pvFileInformation,
	ULONG ulLength,
	FILE_INFORMATION_CLASS InfoClass, 
	const PCHAR szFullName
)
{
	PVOID pvRecord, pvPrevRecord;
	ULONG ulNextOfs = 0;
	NTSTATUS rc = STATUS_SUCCESS;

	if(!szFullName || !pvFileInformation)
		return STATUS_INVALID_PARAMETER;

	pvPrevRecord = NULL;
	pvRecord = pvFileInformation;
	do { /* Until there are no more entries */
		ULONG ulNameLen = 0UL;
		PWCHAR pName = NULL;
		CHAR szName[MAXPATHLEN];
		ANSI_STRING AnsiName;
		UNICODE_STRING UniName;

		/*
		 * Get the name of this file from the info structure. If we
		 * don't recognise the info class, don't examine the entries.
		 */
		if (!NameFromFileInfo (pvRecord, InfoClass, &pName, &ulNameLen))
			break;

		/*
		 * Generate a full (ANSI) pathname by converting the result's
		 * Unicode name to ANSI and joining it with the name of the
		 * directory the search was performed in.
		 */
		memset(szName, 0, sizeof(szName)/sizeof(szName[0]));
		strncpy (szName, szFullName, MAXPATHLEN - 1);
		
		UniName.Buffer = pName;
		UniName.Length = (USHORT)ulNameLen;
		AnsiName.Buffer = NULL;
		if (NT_SUCCESS (RtlUnicodeStringToAnsiString (&AnsiName, 
			&UniName, TRUE))) {
			if (szName[strlen(szName) - 1] != '\\')
				strcat (szName, "\\");
			strcat (szName, AnsiName.Buffer);
			RtlFreeAnsiString (&AnsiName);
		}
		
		if (ShouldHideFile(szName)) {
			/*
			 * Hide this file by removing its entry from the
			 * result buffer.
			 */
			if (*(PULONG)pvRecord != 0) {
				ULONG ulOldLength;

				/*
				 * If it's not the last record, move
				 * everything down on top of it.
				 */
				ulOldLength = *(PULONG)pvRecord;
				memmove (pvRecord, (PVOID)((PUCHAR)pvRecord + *(PULONG)pvRecord), (SIZE_T)((PUCHAR)pvFileInformation + ulLength) - (SIZE_T)((PUCHAR)pvRecord + *(PULONG)pvRecord));
				ulLength -= ulOldLength;

				continue;
			} else {
				if (pvPrevRecord != NULL)
					/* Chop off tail of result list */
					*(PULONG)pvPrevRecord = 0;
				else
					/* No results left */
					rc = STATUS_NO_SUCH_FILE;
			}
		}

		/* Move to next record */
		ulNextOfs = *(PULONG)pvRecord;
		pvPrevRecord = pvRecord;
		pvRecord = (PVOID)((PUCHAR)pvRecord + ulNextOfs);
	} while (ulNextOfs != 0UL);

	return rc;
}

static
NTSTATUS
NTAPI
NewZwQueryDirectoryFile(
	IN HANDLE hFile,
	IN HANDLE hEvent OPTIONAL,
	IN PIO_APC_ROUTINE IoApcRoutine OPTIONAL,
	IN PVOID IoApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK pIoStatusBlock,
	OUT PVOID FileInformationBuffer,
	IN ULONG FileInformationBufferLength,
	IN FILE_INFORMATION_CLASS FileInfoClass,
	IN BOOLEAN bReturnOnlyOneEntry,
	IN PUNICODE_STRING PathMask OPTIONAL,
	IN BOOLEAN bRestartQuery
)
{
	NTSTATUS rc;
	CHAR aProcessName[PROCNAMELEN];
	PCHAR szFullName;
		
	GetProcessName( aProcessName );

	//DBGOUT((" Comparing %s == %s", aProcessName, g_ConfigProcName));
	if(memcmp(aProcessName, g_ConfigProcName, g_uiConfigProcNameLen) == 0)
		return s_fnZwQueryDirectoryFile (hFile, hEvent, IoApcRoutine,
			IoApcContext, pIoStatusBlock, FileInformationBuffer, FileInformationBufferLength,
			FileInfoClass, bReturnOnlyOneEntry, PathMask,
			bRestartQuery);

	/* Find the full name of the dir and check access on it */
	szFullName = ExAllocatePool (PagedPool, MAXPATHLEN);
	if (szFullName != NULL) {
		if (!PathFromHandle (hFile, NULL,/*FileName,*/ szFullName)) {
			ExFreePool (szFullName);
			szFullName = NULL;
		}
	}

	if (szFullName != NULL && IoApcRoutine == NULL && hEvent == NULL) {
		/*
		 * A purely synchronous request. These are relatively simple
		 * to handle and the only type of request that the Win32
		 * subsystem seems to generate.
		 *
		 * The ++k < 30 hack avoids a possible infinite loop when
		 * looking for a single file.
		 */
		int k = 0;
		do {
			rc = s_fnZwQueryDirectoryFile (hFile, NULL,
				NULL, NULL, pIoStatusBlock, FileInformationBuffer,
				FileInformationBufferLength, FileInfoClass,
				bReturnOnlyOneEntry, PathMask, bRestartQuery);
			if (NT_SUCCESS (rc) && szFullName != NULL)
				rc = ProcessDirEntries (FileInformationBuffer,
				FileInformationBufferLength,	FileInfoClass, szFullName);
			bRestartQuery = FALSE;
		} while (bReturnOnlyOneEntry && rc == STATUS_NO_SUCH_FILE &&
			++k < 30);
	} else {
		/*
		 * An asynchronous request, either using an event or async.
		 * procedure call. We can't handle this, so just pass it
		 * straight through to the normal kernel function.
		 */
		rc = s_fnZwQueryDirectoryFile (hFile, hEvent, IoApcRoutine,
			IoApcContext, pIoStatusBlock, FileInformationBuffer, FileInformationBufferLength,
			FileInfoClass, bReturnOnlyOneEntry, PathMask,
			bRestartQuery);
	}

	if (szFullName != NULL)
		ExFreePool (szFullName);

	return rc;
}

/*
 *	NT's ZwQuerySystemInformation() returns a linked list of processes.
 *	The function below imitates it, except it removes from the list any
 *	process who's name begins with g_ConfigProcName.
 */

static
NTSTATUS 
NTAPI
NewZwQuerySystemInformation(
	IN ULONG SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength
)
{
	NTSTATUS rc;
	CHAR aProcessName[PROCNAMELEN];
  
	rc = s_fnZwQuerySystemInformation(
									SystemInformationClass,
									SystemInformation,
									SystemInformationLength,
									ReturnLength );

	if(!NT_SUCCESS(rc) && rc != STATUS_INFO_LENGTH_MISMATCH)
		return rc;

	/* This should not happen. */
	if(!SystemInformation)
		return rc;

	GetProcessName( aProcessName );

	// double check the process name, if it starts w/ g_ConfigProcName DO NOT
	// apply any stealth
	if(0 == memcmp(aProcessName, g_ConfigProcName, g_uiConfigProcNameLen)) {

	}	else {		
		switch(SystemInformationClass) {
			case SystemModuleInformation:
				{
					// Loop through the list looking for ourself. 
					// If we find ourself then we need to:
					// 1) decrement the size of the list
					// 2) move the data into the new list and shift the data
					// 3) return the data to the user.
					NTSTATUS ret;
					ULONG i, *n;
					MDL *mdl, *mdln;
					ULONG *q;
					PULONG virt_addr, virt_addrn;
					PSYSTEM_MODULE_INFORMATION p;
					BOOLEAN bFound = FALSE;
					PCHAR c = NULL;

					virt_addrn = (PULONG)ExAllocatePool(PagedPool, sizeof(ULONG));

					mdln = IoAllocateMdl(virt_addrn, sizeof(ULONG), FALSE, FALSE, NULL);
					if (mdln == NULL) {
						ExFreePool(virt_addrn);
						break;
					}

					MmProbeAndLockPages(mdln, KernelMode, IoModifyAccess);

					n = (ULONG *)MmMapLockedPages(mdln, UserMode); 

					ret = s_fnZwQuerySystemInformation(SystemModuleInformation, n, 0, n);
					
					
					if(ret != STATUS_INFO_LENGTH_MISMATCH) {
						MmUnmapLockedPages(n, mdln);
						MmUnlockPages(mdln);
						IoFreeMdl(mdln);
						ExFreePool(virt_addrn);
						break;
					}
					
					virt_addr = (PULONG)ExAllocatePool(PagedPool, (*n) * sizeof(*q));

					mdl = IoAllocateMdl(virt_addr, (*n) * sizeof(*q), FALSE, FALSE, NULL);
					if (mdl == NULL) {
						ExFreePool(virt_addr);
						break;
					}

					MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);

					q = (ULONG *)MmMapLockedPages(mdl, UserMode); 

					ret = s_fnZwQuerySystemInformation(SystemModuleInformation, q, (*n) * sizeof(*q), 0);
					

					if(!NT_SUCCESS(ret)) {
						MmUnmapLockedPages(n, mdln);
						MmUnlockPages(mdln);
						IoFreeMdl(mdln);
						ExFreePool(virt_addrn);

						MmUnmapLockedPages(q, mdl);
						MmUnlockPages(mdl);
						IoFreeMdl(mdl);
						ExFreePool(virt_addr);
						break;
					}
					
					p = (PSYSTEM_MODULE_INFORMATION)(q + 1);
					for (i = 0; i < *q; i++) {
						if (_strnicmp( p[i].ImageName + p[i].ModuleNameOffset, g_DriverName, g_uiDriverNameLen) == 0) {
							bFound = TRUE;
							break;
						}
					}

					if(!SystemInformationLength) {
						if(bFound) { // They are requesting the size.
							if(ReturnLength)
								*ReturnLength = ((*n) - 1);
						} else {
							if(ReturnLength)
								*ReturnLength = (*n);
						}

						MmUnmapLockedPages(n, mdln);
						MmUnlockPages(mdln);
						IoFreeMdl(mdln);
						ExFreePool(virt_addrn);
						
						MmUnmapLockedPages(q, mdl);
						MmUnlockPages(mdl);
						IoFreeMdl(mdl);
						ExFreePool(virt_addr);
						break;
					}
									
					if((bFound && SystemInformationLength != ((*n - 1) * sizeof(*q) )) || (!bFound && SystemInformationLength != ((*n) * sizeof(*q)))) {
						MmUnmapLockedPages(q, mdl);
						MmUnlockPages(mdl);
						IoFreeMdl(mdl);
						ExFreePool(virt_addr);
						break;
					}
				
					MmUnmapLockedPages(n, mdln);
					MmUnlockPages(mdln);
					IoFreeMdl(mdln);
					ExFreePool(virt_addrn);

					if(bFound)
						*((ULONG *)SystemInformation) = (*q) - 1;
					else
						*((ULONG *)SystemInformation) = (*q);

					c = (PCHAR) ((PULONG)SystemInformation + 1);
					p = (PSYSTEM_MODULE_INFORMATION)(q + 1);
					for(i = 0; i < *q; i++) {
							if(_strnicmp(p[i].ImageName + p[i].ModuleNameOffset, g_DriverName, g_uiDriverNameLen) != 0) {
								memcpy((PVOID)c, (PVOID)(&p[i]), sizeof(SYSTEM_MODULE_INFORMATION));
								c += sizeof(SYSTEM_MODULE_INFORMATION);
							}
					}
	
					MmUnmapLockedPages(q, mdl);
					MmUnlockPages(mdl);
					IoFreeMdl(mdl);
					ExFreePool(virt_addr);
				}
				break;
			default:
				break;
		}
	}

	return(rc);	
}

static
NTSTATUS
NTAPI
NewZwOpenFile(
	PHANDLE phFile,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK pIoStatusBlock,
	ULONG ShareMode,
	ULONG OpenMode
)
{
	NTSTATUS rc;
	CHAR aProcessName[PROCNAMELEN];	
	PCHAR szFullName;

	GetProcessName(aProcessName);

	if(0 == memcmp(aProcessName, g_ConfigProcName, g_uiConfigProcNameLen)) {
			return s_fnZwOpenFile (phFile, DesiredAccess,
			ObjectAttributes, pIoStatusBlock, ShareMode,
			OpenMode);
	}

	if(ObjectAttributes) {
		/* Find the full name of the file and check access on it */
		szFullName = ExAllocatePool (PagedPool, MAXPATHLEN);
		if (szFullName != NULL) {
			if (PathFromHandle (ObjectAttributes->RootDirectory, ObjectAttributes->ObjectName, szFullName)) {
				if (ShouldHideFile(szFullName)) {
					ExFreePool (szFullName);
					/* Pretend it doesn't exist */
					return STATUS_NO_SUCH_FILE;
				}
			}
			ExFreePool (szFullName);
		}
	}

	rc = s_fnZwOpenFile (phFile, DesiredAccess, ObjectAttributes,
		pIoStatusBlock, ShareMode, OpenMode);

	return rc;
}

/*
 * Hook of ZwCreateFile(); disallows protected files from being opened.
 */
static
NTSTATUS
NTAPI
NewZwCreateFile (
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize OPTIONAL,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer OPTIONAL,
	IN ULONG EaLength
)
{
	NTSTATUS rc;
	PCHAR szFullName;
	CHAR aProcessName[PROCNAMELEN];	

	GetProcessName( aProcessName );

	if(0 == memcmp(aProcessName, g_ConfigProcName, g_uiConfigProcNameLen))
		return s_fnZwCreateFile (FileHandle, DesiredAccess,
			ObjectAttributes, IoStatusBlock, AllocationSize,
			FileAttributes, ShareAccess, CreateDisposition,
			CreateOptions, EaBuffer, EaLength);

	if(ObjectAttributes) {
		/* Find the full name of the file and check access on it */
		szFullName = ExAllocatePool (PagedPool, MAXPATHLEN);
		if (szFullName != NULL) {
			if (PathFromHandle (ObjectAttributes->RootDirectory, 
				ObjectAttributes->ObjectName, szFullName)) {
				if (ShouldHideFile(szFullName)) {
					ExFreePool (szFullName);
					/* Pretend it doesn't exist */
					return STATUS_NO_SUCH_FILE;
				}
			}
			ExFreePool (szFullName);
		}
	}
	
	rc = s_fnZwCreateFile (FileHandle, DesiredAccess, ObjectAttributes,
		IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
		CreateDisposition, CreateOptions, EaBuffer, EaLength);

	return rc;
}

/*
 * Hook of ZwCreateKey() don't allow protected keys to be opened.
 */
static
NTSTATUS
NTAPI
NewZwCreateKey (
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG TitleIndex,
	IN PUNICODE_STRING Class OPTIONAL,
	IN ULONG CreateOptions,
	OUT PULONG Disposition OPTIONAL
)
{
	NTSTATUS rc;
	PCHAR szFullName;

	if(ObjectAttributes) {
		/* Find the full name of the key and check access on it */
		szFullName = ExAllocatePool (PagedPool, MAXPATHLEN);
		if(szFullName != NULL) {
			if(PathFromHandle (ObjectAttributes->RootDirectory, ObjectAttributes->ObjectName, szFullName)) {
				AdjustKeyName (szFullName);
				if(ShouldHideReg(szFullName)) {
					ExFreePool (szFullName);
					return STATUS_NO_SUCH_FILE;
				}
			}
			ExFreePool (szFullName);
		}
	}

	rc = s_fnZwCreateKey (KeyHandle, DesiredAccess, ObjectAttributes,
		TitleIndex, Class, CreateOptions, Disposition);

	return rc;
}


/*
 * Hook of ZwOpenKey() don't allow protected keys to be opened.
 */
static NTSTATUS NTAPI NewZwOpenKey (
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes
)
{
	NTSTATUS rc;
	PCHAR szFullName;

	/* Find the full name of the key and check access on it */
	if(ObjectAttributes) {
		szFullName = ExAllocatePool (PagedPool, MAXPATHLEN);
		if (szFullName != NULL) {
			if (PathFromHandle (ObjectAttributes->RootDirectory, 
				ObjectAttributes->ObjectName, szFullName)) {
				AdjustKeyName (szFullName);
				if (ShouldHideReg(szFullName)) {
					ExFreePool (szFullName);
					return STATUS_NO_SUCH_FILE;
				}
			}
			ExFreePool (szFullName);
		}
	}
	
	rc = s_fnZwOpenKey (KeyHandle, DesiredAccess, ObjectAttributes);

	return rc;
}


/*
 * Hook of ZwEnumerateKey() hide protected keys
 */
static
NTSTATUS
NTAPI
NewZwEnumerateKey (
	IN HANDLE KeyHandle,
	IN ULONG Index,
	IN KEY_INFORMATION_CLASS KeyInformationClass,
	OUT PVOID KeyInformation,
	IN ULONG Length,
	OUT PULONG ResultLength
)
{
	NTSTATUS rc;
	PCHAR szFullName;
	PWCHAR pName = NULL;
	PULONG pulNameLen = NULL;

	/* Find the full name of the key and check access on it */
	szFullName = ExAllocatePool (PagedPool, MAXPATHLEN);
	if (szFullName != NULL) {
		if (!PathFromHandle (KeyHandle, NULL, szFullName)) {
			ExFreePool (szFullName);
			szFullName = NULL;
		}
	}

	rc = s_fnZwEnumerateKey (KeyHandle, Index, KeyInformationClass,
		KeyInformation, Length, ResultLength);

	if (NT_SUCCESS(rc) && szFullName != NULL && KeyInformation != NULL) {
		switch (KeyInformationClass) {
		case KeyBasicInformation:
			pName = ((PKEY_BASIC_INFORMATION)KeyInformation)->Name;
			pulNameLen = &((PKEY_BASIC_INFORMATION)KeyInformation)->NameLength;
			break;
		case KeyNodeInformation:
			pName = ((PKEY_NODE_INFORMATION)KeyInformation)->Name;
			pulNameLen = &((PKEY_NODE_INFORMATION)KeyInformation)->NameLength;
			break;
		case KeyNameInformation:
			pName = ((PKEY_NAME_INFORMATION)KeyInformation)->Name;
			pulNameLen = &((PKEY_NAME_INFORMATION)KeyInformation)->NameLength;
			break;
		case KeyFullInformation:
			/*
			 * This information class gives no info about
			 * the names of keys.
			 */
			break;
		default:
			DBGOUT(("NewZwEnumerateKey(): unknown class %d",
				KeyInformationClass));
		}

		if (pName != NULL && pulNameLen != NULL) {
			UNICODE_STRING us;
			ANSI_STRING as;

			strcat (szFullName, "\\");

			us.Length = us.MaximumLength = (USHORT)*pulNameLen;
			us.Buffer = pName;
			as.Length = 0;
			as.MaximumLength = (USHORT)(MAXPATHLEN - (strlen(szFullName) - 1));
			as.Buffer = szFullName + strlen (szFullName);
			rc = RtlUnicodeStringToAnsiString (&as, &us, FALSE);
			if (NT_SUCCESS (rc)) {
				as.Buffer[as.Length] = '\0';
				AdjustKeyName (szFullName);
				if (ShouldHideReg(szFullName)) {
					wcscpy (pName, L"temp");
					*pulNameLen = 4;
				}
			}
		}
	}

	if (szFullName != NULL)
		ExFreePool (szFullName);

	return rc;
}


/*
 * Hook of ZwEnumerateValueKey(); hide protected values
 * XXX not yet
 */
static
NTSTATUS
NTAPI
NewZwEnumerateValueKey (
	IN HANDLE  KeyHandle,
	IN ULONG  Index,
	IN KEY_VALUE_INFORMATION_CLASS  KeyValueInformationClass,
	OUT PVOID  KeyValueInformation,
	IN ULONG  Length,
	OUT PULONG  ResultLength
)
{
	NTSTATUS rc;
	PCHAR szFullName;

	/* Find the full name of the key and check access on it */
	szFullName = ExAllocatePool (PagedPool, MAXPATHLEN);
	if (szFullName != NULL) {
		if (!PathFromHandle (KeyHandle, NULL, szFullName)) {
			ExFreePool (szFullName);
			szFullName = NULL;
		}
	}

	rc = s_fnZwEnumerateValueKey(KeyHandle, Index,
		KeyValueInformationClass, KeyValueInformation,
		Length, ResultLength);

	if (szFullName != NULL)
		ExFreePool (szFullName);

	return rc;
}


/*
 * Convert some common Windows NT kernel registry paths to more familiar
 * Win32-style names.
 */
VOID
AdjustKeyName(
	PCHAR szKeyName
)
{
	PCHAR p;
	if(!szKeyName)
		return;

	if (_strnicmp (szKeyName, "\\\\", 2) == 0) {
		memmove (szKeyName, szKeyName + 1, strlen (szKeyName));
	}

#define HKUS1 "\\REGISTRY\\USER\\S"
#define HKUS2 "HKEY_CURRENT_USER\\"
	if (_strnicmp (szKeyName, HKUS1, sizeof(HKUS1) - 1) == 0) {
		p = strchr (szKeyName + sizeof(HKUS1) + 1, '\\');
		if (p == NULL)
			return;
		p++;
		memmove (szKeyName + sizeof(HKUS2) - 1, p, strlen (p) + 1);
		memcpy (szKeyName, HKUS2, sizeof(HKUS2) - 1);
#define HKU1 "\\REGISTRY\\USER\\"
#define HKU2 "HKEY_USERS\\"
	} else if (_strnicmp (szKeyName, HKU1, sizeof(HKU1) - 1) == 0) {
		p = szKeyName + sizeof(HKU1);
		memmove (szKeyName + sizeof(HKU2) - 1, p, strlen (p) + 1);
		memcpy (szKeyName, HKU2, sizeof(HKU2) - 1);
#define HKM1 "\\REGISTRY\\MACHINE\\"
#define HKM2 "HKEY_LOCAL_MACHINE\\"
	} else if (_strnicmp (szKeyName, HKM1, sizeof(HKM1) - 1) == 0) {
		p = szKeyName + sizeof(HKM1) - 1;
		memmove (szKeyName + sizeof(HKM2) - 1, p, strlen (p) + 1);
		memcpy (szKeyName, HKM2, sizeof(HKM2) - 1);
	}
}

/*
	If running on Windows 2000 then we use simple offset, however, if we are running on
	XP or higher we use a trick from Edgar Barbosa's paper "Finding some 
	non-exported kernel variables in Windows XP".
*/
MODULE_ENTRY *FindPsModuleList(IN const DRIVER_OBJECT *pDriverObject)
{
	PMODULE_ENTRY pModuleListStart = NULL;

	if(!pDriverObject)
		return FALSE;

#if (_WIN32_WINNT == 0x0500)
	pModuleListStart = *((PMODULE_ENTRY*)((DWORD)pDriverObject + PSLOADEDMODULE_OFFSET));
#else
	__asm {
		mov eax, fs:[0x34]; // KdVersionBlock
		mov eax, [eax+0x70]; // PsLoadedModuleList
		mov pModuleListStart, eax;
	}
#endif

	return pModuleListStart;
}

BOOLEAN RemoveDriverFromModuleList(IN const DRIVER_OBJECT *pDriverObject)
{
	PMODULE_ENTRY pModuleListStart = NULL, pCurrentModuleListEntry = NULL;
	ANSI_STRING astrDriverName;
	UNICODE_STRING ustrDriverName;

	if(!pDriverObject)
		return FALSE;

	pModuleListStart = FindPsModuleList(pDriverObject);
	if(!pModuleListStart)
		return FALSE;

	RtlInitAnsiString(&astrDriverName, g_DriverName);
	if(!NT_SUCCESS(RtlAnsiStringToUnicodeString(&ustrDriverName, &astrDriverName, TRUE)))
		return FALSE;

	pCurrentModuleListEntry = pModuleListStart;
	while((PMODULE_ENTRY)pCurrentModuleListEntry->lModuleList.Flink != pModuleListStart) {
		if ((pCurrentModuleListEntry->unk1 != 0x00000000) && (pCurrentModuleListEntry->strDriverPath.Length != 0)) {
			DBGOUT(("RemoveDriverFromModuleList: Comparing %S to %S", ustrDriverName.Buffer, pCurrentModuleListEntry->strDriverName.Buffer));
			if(RtlCompareUnicodeString(&ustrDriverName, &(pCurrentModuleListEntry->strDriverName), FALSE) == 0) {
				*((DWORD *)pCurrentModuleListEntry->lModuleList.Blink) = (DWORD)pCurrentModuleListEntry->lModuleList.Flink;
				pCurrentModuleListEntry->lModuleList.Flink->Blink = pCurrentModuleListEntry->lModuleList.Blink;
				RtlFreeUnicodeString(&ustrDriverName);
				return TRUE;
			}
		}
		
		pCurrentModuleListEntry =  (MODULE_ENTRY *)pCurrentModuleListEntry->lModuleList.Flink;
	}

	RtlFreeUnicodeString(&ustrDriverName);
	return FALSE;
	
}

NTSTATUS UninitAntiDetection()
{
#ifdef ENABLE_ANTIDETECTION
	if(!s_AntiDetectionInit) // We were never initialized.
		return STATUS_SUCCESS;
		
	if(!SetSystemCallIndex(SYSTEMSERVICE(ZwQueryDirectoryFile), (PVOID)s_fnZwQueryDirectoryFile, NULL))
		return STATUS_UNSUCCESSFUL;

	if(!SetSystemCallIndex(SYSTEMSERVICE(ZwQuerySystemInformation), (PVOID)s_fnZwQuerySystemInformation, NULL))
		return STATUS_UNSUCCESSFUL;

	if(!SetSystemCallIndex(SYSTEMSERVICE(ZwOpenFile), (PVOID)s_fnZwOpenFile, NULL))
		return STATUS_UNSUCCESSFUL;

	if(!SetSystemCallIndex(SYSTEMSERVICE(ZwCreateFile), (PVOID)s_fnZwCreateFile, NULL))
		return STATUS_UNSUCCESSFUL;
	
	if(!SetSystemCallIndex(SYSTEMSERVICE(ZwCreateKey), (PVOID)s_fnZwCreateKey, NULL))
		return STATUS_UNSUCCESSFUL;

	if(!SetSystemCallIndex(SYSTEMSERVICE(ZwOpenKey), (PVOID)s_fnZwOpenKey, NULL))
		return STATUS_UNSUCCESSFUL;

	if(!SetSystemCallIndex(SYSTEMSERVICE(ZwEnumerateKey), (PVOID)s_fnZwEnumerateKey, NULL))
		return STATUS_UNSUCCESSFUL;

	if(!SetSystemCallIndex(SYSTEMSERVICE(ZwEnumerateValueKey), (PVOID)s_fnZwEnumerateValueKey, NULL))
		return STATUS_UNSUCCESSFUL;
#endif

	s_AntiDetectionInit = FALSE;

	DBGOUT(("UninitAntiDetection"));
	return STATUS_SUCCESS;
}

NTSTATUS InitAntiDetection(const DRIVER_OBJECT *pDriverObject)
{
#ifdef ENABLE_ANTIDETECTION
	if(!SetSystemCallIndex(SYSTEMSERVICE(ZwQueryDirectoryFile), NewZwQueryDirectoryFile, (PVOID *)&s_fnZwQueryDirectoryFile))
		return STATUS_UNSUCCESSFUL;

	if(!SetSystemCallIndex(SYSTEMSERVICE(ZwQuerySystemInformation), NewZwQuerySystemInformation, (PVOID *)&s_fnZwQuerySystemInformation))
		return STATUS_UNSUCCESSFUL;

	if(!SetSystemCallIndex(SYSTEMSERVICE(ZwOpenFile), NewZwOpenFile, (PVOID *)&s_fnZwOpenFile))
		return STATUS_UNSUCCESSFUL;

	if(!SetSystemCallIndex(SYSTEMSERVICE(ZwCreateFile), NewZwCreateFile, (PVOID *)&s_fnZwCreateFile))
		return STATUS_UNSUCCESSFUL;

	if(!SetSystemCallIndex(SYSTEMSERVICE(ZwCreateKey), NewZwCreateKey, (PVOID *)&s_fnZwCreateKey))
		return STATUS_UNSUCCESSFUL;

	if(!SetSystemCallIndex(SYSTEMSERVICE(ZwOpenKey), NewZwOpenKey, (PVOID *)&s_fnZwOpenKey))
		return STATUS_UNSUCCESSFUL;

	if(!SetSystemCallIndex(SYSTEMSERVICE(ZwEnumerateKey), NewZwEnumerateKey, (PVOID *)&s_fnZwEnumerateKey))
		return STATUS_UNSUCCESSFUL;

	if(!SetSystemCallIndex(SYSTEMSERVICE(ZwEnumerateValueKey), NewZwEnumerateValueKey, (PVOID *)&s_fnZwEnumerateValueKey))
		return STATUS_UNSUCCESSFUL;

	if(!RemoveDriverFromModuleList(pDriverObject))
		return STATUS_UNSUCCESSFUL;
	
	DBGOUT(("InitAntiDetection: returning!"));
	s_AntiDetectionInit = TRUE;
#endif
  return STATUS_SUCCESS;
}
