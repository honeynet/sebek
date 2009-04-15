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

#ifndef UTIL_H
#define UTIL_H

#if _MSC_VER > 1000
#pragma once
#endif

#include "tib.h"

// Length of process name (rounded up to next DWORD)
#define PROCNAMELEN     20
// Maximum length of NT process name
#define NT_PROCNAMELEN  16

// Needed because Win2k DDK does not define it
#ifndef min
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif

#define MAXPATHLEN 1024

/*
 * Undocumented kernel functions we need to call.
 */

NTKERNELAPI NTSTATUS ObQueryNameString (
	IN PVOID                        Object,
	IN OUT PUNICODE_STRING		Name,
	/* ^ this should strictly be PBOJECT_NAME_INFORMATION */
	IN ULONG                        MaximumLength,
	OUT PULONG                      ActualLength
);

void GetProcessNameOffset();
BOOLEAN GetProcessName(PCHAR theName);

ULONG gProcessNameOffset;

NTSTATUS
RegGetSz(
    IN      ULONG  RelativeTo,               
    IN CONST PWSTR  Path,
    IN      PWSTR  ParameterName,
    IN OUT  PUNICODE_STRING ParameterValue
    );

NTSTATUS
RegGetDword(
    IN     ULONG  RelativeTo,               
    IN     PWSTR  Path,
    IN     PWSTR  ParameterName,
    IN OUT PULONG ParameterValue
    );

__inline char *_strrchr(IN const char *p, IN int ch)
{
	char *save;

	if(!p)
		return NULL;

	for (save = NULL;; ++p) {
		if (*p == ch)
			save = (char *)p;
		if (!*p)
			return(save);
	}
}

BOOLEAN PathFromHandle(
		IN HANDLE hKey, 
		IN PUNICODE_STRING lpszSubKeyVal,
		OUT PCHAR fullname
		);

void ConvertToSecondsFrom1970(
		IN CONST PLARGE_INTEGER pFrom,
		OUT PULONG pTo,
		OUT PULONG pMilliseconds);

BOOLEAN RemoveModule(void);


typedef enum _TOKEN_INFORMATION_CLASS {
    TokenUser = 1,
    TokenGroups,
    TokenPrivileges,
    TokenOwner,
    TokenPrimaryGroup,
    TokenDefaultDacl,
    TokenSource,
    TokenType,
    TokenImpersonationLevel,
    TokenStatistics,
    TokenRestrictedSids
} TOKEN_INFORMATION_CLASS, *PTOKEN_INFORMATION_CLASS;

typedef PVOID PSID;     

typedef struct _SID_AND_ATTRIBUTES {
    PSID Sid;
    ULONG Attributes;
} SID_AND_ATTRIBUTES, * PSID_AND_ATTRIBUTES;

typedef struct _TOKEN_USER {
    SID_AND_ATTRIBUTES User;
} TOKEN_USER, *PTOKEN_USER;

#define TOKEN_QUERY             (0x0008)

HANDLE PsReferencePrimaryToken(PEPROCESS Process );

NTSTATUS RtlConvertSidToUnicodeString(
    PUNICODE_STRING SidString, 
    PVOID Sid, BOOLEAN AllocateString );

NTSTATUS ZwQueryInformationToken(
    HANDLE Token, 
    TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID TokenInformation, 
    ULONG TokenInformationLength, PULONG ReturnLength );

NTSTATUS ObOpenObjectByPointer(
    PVOID Object, 
    ULONG Flags, 
    PACCESS_STATE AccessState, 
    ACCESS_MASK DesiredAccess, 
    POBJECT_TYPE ObjectType, 
    KPROCESSOR_MODE AccessMode, 
    PHANDLE Handle );


BOOLEAN GetUserSIDFromProcess(IN EPROCESS *pProcess, OUT UNICODE_STRING *pusSID);

#endif
