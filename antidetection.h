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

#ifndef ANTIDETECTION_H
#define ANTIDETECTION_H

#if _MSC_VER > 1000
#pragma once
#endif

#include <ntddk.h>
#include "stdarg.h"
#include "stdio.h"
#include "ntiologc.h"
#include "system_service.h"
#include "nt.h"
#include "windef.h"

typedef struct _MODULE_ENTRY {
	LIST_ENTRY lModuleList;
	DWORD  unknown[4];
	DWORD  base;
	DWORD  dwDriverStart;
	DWORD  unk1;
	UNICODE_STRING strDriverPath;
	UNICODE_STRING strDriverName;
} MODULE_ENTRY, *PMODULE_ENTRY;

struct _SYSTEM_THREADS
{
        LARGE_INTEGER           KernelTime;
        LARGE_INTEGER           UserTime;
        LARGE_INTEGER           CreateTime;
        ULONG                           WaitTime;
        PVOID                           StartAddress;
        CLIENT_ID                       ClientIs;
        KPRIORITY                       Priority;
        KPRIORITY                       BasePriority;
        ULONG                           ContextSwitchCount;
        ULONG                           ThreadState;
        KWAIT_REASON            WaitReason;
};

struct _SYSTEM_PROCESSES
{
        ULONG                           NextEntryDelta;
        ULONG                           ThreadCount;
        ULONG                           Reserved[6];
        LARGE_INTEGER           CreateTime;
        LARGE_INTEGER           UserTime;
        LARGE_INTEGER           KernelTime;
        UNICODE_STRING          ProcessName;
        KPRIORITY                       BasePriority;
        ULONG                           ProcessId;
        ULONG                           InheritedFromProcessId;
        ULONG                           HandleCount;
        ULONG                           Reserved2[2];
        VM_COUNTERS                     VmCounters;
        IO_COUNTERS                     IoCounters; //windows 2000 only
        struct _SYSTEM_THREADS          Threads[1];
};

// added -Creative
struct _SYSTEM_PROCESSOR_TIMES
{
		LARGE_INTEGER					IdleTime;
		LARGE_INTEGER					KernelTime;
		LARGE_INTEGER					UserTime;
		LARGE_INTEGER					DpcTime;
		LARGE_INTEGER					InterruptTime;
		ULONG							InterruptCount;
};

#if 0
typedef enum _WXPFILE_INFORMATION_CLASS {
// end_wdm
    FileDirectoryInformation         = 1,
    FileFullDirectoryInformation,   // 2
    FileBothDirectoryInformation,   // 3
    FileBasicInformation,           // 4  wdm
    FileStandardInformation,        // 5  wdm
    FileInternalInformation,        // 6
    FileEaInformation,              // 7
    FileAccessInformation,          // 8
    FileNameInformation,            // 9
    FileRenameInformation,          // 10
    FileLinkInformation,            // 11
    FileNamesInformation,           // 12
    FileDispositionInformation,     // 13
    FilePositionInformation,        // 14 wdm
    FileFullEaInformation,          // 15
    FileModeInformation,            // 16
    FileAlignmentInformation,       // 17
    FileAllInformation,             // 18
    FileAllocationInformation,      // 19
    FileEndOfFileInformation,       // 20 wdm
    FileAlternateNameInformation,   // 21
    FileStreamInformation,          // 22
    FilePipeInformation,            // 23
    FilePipeLocalInformation,       // 24
    FilePipeRemoteInformation,      // 25
    FileMailslotQueryInformation,   // 26
    FileMailslotSetInformation,     // 27
    FileCompressionInformation,     // 28
    FileObjectIdInformation,        // 29
    FileCompletionInformation,      // 30
    FileMoveClusterInformation,     // 31
    FileQuotaInformation,           // 32
    FileReparsePointInformation,    // 33
    FileNetworkOpenInformation,     // 34
    FileAttributeTagInformation,    // 35
    FileTrackingInformation,        // 36
    FileIdBothDirectoryInformation,     // 37
    FileIdFullDirectoryInformation, // 38
    FileValidDataLengthInformation, // 39
    FileShortNameInformation,       // 40
        FileMaximumInformation
// begin_wdm
} WXPFILE_INFORMATION_CLASS, *PWXPFILE_INFORMATION_CLASS;
#endif

typedef struct _FILE_DIRECTORY_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_DIRECTORY_INFORMATION, *PFILE_DIRECTORY_INFORMATION;

typedef struct _FILE_FULL_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    WCHAR FileName[1];
} FILE_FULL_DIR_INFORMATION, *PFILE_FULL_DIR_INFORMATION;

typedef struct _FILE_ID_FULL_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_FULL_DIR_INFORMATION, *PFILE_ID_FULL_DIR_INFORMATION;

typedef struct _FILE_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    WCHAR FileName[1];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;

typedef struct _FILE_ID_BOTH_DIR_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, *PFILE_ID_BOTH_DIR_INFORMATION;

typedef struct _FILE_NAMES_INFORMATION {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    ULONG FileNameLength;
    WCHAR FileName[1];
} FILE_NAMES_INFORMATION, *PFILE_NAMES_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
ZwQueryDirectoryFile(
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
);

typedef NTSTATUS (NTAPI *ZWQUERYDIRECTORYFILE)(
    HANDLE hFile,
        HANDLE hEvent,
        PIO_APC_ROUTINE IoApcRoutine,
        PVOID IoApcContext,
        PIO_STATUS_BLOCK pIoStatusBlock,
        PVOID FileInformationBuffer,
        ULONG FileInformationBufferLength,
        FILE_INFORMATION_CLASS FileInfoClass,
        BOOLEAN bReturnOnlyOneEntry,
        PUNICODE_STRING PathMask,
        BOOLEAN bRestartQuery
);

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
);

typedef NTSTATUS (NTAPI *ZWQUERYSYSTEMINFORMATION)(
        ULONG SystemInformationCLass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
);

typedef  NTSTATUS (NTAPI *ZWCREATEKEY) (
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG TitleIndex,
	IN PUNICODE_STRING Class OPTIONAL,
	IN ULONG CreateOptions,
	OUT PULONG Disposition OPTIONAL
);


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
);

// declare function pointer
typedef NTSTATUS (NTAPI *ZWOPENFILE)(
	PHANDLE phFile,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK pIoStatusBlock,
	ULONG ShareMode,
	ULONG OpenMode
);

static
NTSTATUS
NTAPI
NewZwCreateFile(
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
);

// declare function pointer
typedef NTSTATUS (NTAPI *ZWCREATEFILE)(
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
);

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
);

static
NTSTATUS
NTAPI
NewZwOpenKey (
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS (NTAPI *ZWOPENKEY) (
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes
);

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
);

typedef NTSTATUS (NTAPI *ZWENUMERATEKEY) (
	IN HANDLE KeyHandle,
	IN ULONG Index,
	IN KEY_INFORMATION_CLASS KeyInformationClass,
	OUT PVOID KeyInformation,
	IN ULONG Length,
	OUT PULONG ResultLength
);

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
);

typedef NTSTATUS (NTAPI *ZWENUMERATEVALUEKEY) (
	IN HANDLE KeyHandle,
	IN ULONG Index,
	IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	OUT PVOID KeyValueInformation,
	IN ULONG Length,
	OUT PULONG ResultLength
);

NTSTATUS ZwDeleteFile(IN HANDLE FileHandle);

VOID AdjustKeyName(PCHAR szKeyName);
NTSTATUS InitAntiDetection(const DRIVER_OBJECT *pDriverObject);
NTSTATUS UninitAntiDetection();

// Our REAL function pointers
static ZWQUERYSYSTEMINFORMATION   s_fnZwQuerySystemInformation = NULL;
static ZWQUERYDIRECTORYFILE       s_fnZwQueryDirectoryFile = NULL;
static ZWOPENFILE									s_fnZwOpenFile = NULL;
static ZWCREATEFILE								s_fnZwCreateFile = NULL;
static ZWCREATEKEY								s_fnZwCreateKey = NULL;
static ZWOPENKEY									s_fnZwOpenKey = NULL;
static ZWENUMERATEKEY							s_fnZwEnumerateKey = NULL;
static ZWENUMERATEVALUEKEY				s_fnZwEnumerateValueKey = NULL;

static BOOLEAN s_AntiDetectionInit = FALSE;

#endif
