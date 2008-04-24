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

/*
 * This code was originally written by Blake R. Watts  (blake@blakewatts.com)
 * and graciously donated to the The Honeynet Project.
 */

#pragma once
#include <ntddk.h>
#include "system_service.h"
#include "logging.h"

// WINDOWS 2000
#if (_WIN32_WINNT == 0x0500)
#define SYSCALL_INDEX_ZWSECURECONNECTPORT       0xB8
#define SYSCALL_INDEX_ZWCREATETHREAD			0x2E
#endif

// WINDOWS XP
#if (_WIN32_WINNT == 0x0501)
#define SYSCALL_INDEX_ZWSECURECONNECTPORT       0xD2
#define SYSCALL_INDEX_ZWCREATETHREAD			0x35
#endif

// Windows 2003
#if (_WIN32_WINNT == 0x0502)
#define SYSCALL_INDEX_ZWSECURECONNECTPORT       0xDA
#define SYSCALL_INDEX_ZWCREATETHREAD			0x37
#endif


//
// LPC/CSRSS Undocumented Information
//
typedef struct _PORT_MESSAGE {
   USHORT      DataSize;
   USHORT      MessageSize;
   USHORT      MessageType;
   USHORT      VirtualRangesOffset;
   CLIENT_ID   ClientId;
   ULONG       MessageId;
   ULONG       SectionSize;
   // UCHAR Data[];
}PORT_MESSAGE, *PPORT_MESSAGE;

typedef struct _PORT_SECTION_WRITE {
   ULONG Length;
   HANDLE hSection;
   ULONG SectionOffset;
   ULONG ViewSize;
   PVOID ViewBase;
   PVOID TargetViewBase;
} PORT_SECTION_WRITE, *PPORT_SECTION_WRITE;

typedef struct _PORT_SECTION_READ {
   ULONG Length;
   ULONG ViewSize;
   ULONG ViewBase;
} PORT_SECTION_READ, *PPORT_SECTION_READ;


//
// TODO: Check the current version before choosing an opcode
//
#define  OPCODE_READ_CONSOLE        0x2021D
#define  OPCODE_WRITE_CONSOLE       0x2021E

typedef struct _CSRSS_MESSAGE {
   ULONG Unknown1;
   ULONG OpCode;
   NTSTATUS Status;
   ULONG Unknown2;
} CSRSS_MESSAGE, *PCSRSS_MESSAGE;

#define CONSOLE_WRITE_INFO_MESSAGE_BUFFER_SIZE  80
#define CONSOLE_READ_INFO_MESSAGE_BUFFER_SIZE   82

typedef struct _CSR_CONSOLE_WRITE_INFORMATION {
   LONG Console;
   HANDLE OutputHandle;
   CHAR MessageBuffer[CONSOLE_WRITE_INFO_MESSAGE_BUFFER_SIZE];
   PVOID MessageBufferPtr;
   ULONG MessageBufferSize;
   ULONG Unknown1;
   UCHAR Unknown2;
   BOOLEAN Unicode;
   USHORT Unknown3;
   ULONG Unknown4;
} CSR_CONSOLE_WRITE_INFORMATION, *PCSR_CONSOLE_WRITE_INFORMATION;

typedef struct _CSR_CONSOLE_READ_INFORMATION {
   LONG ConsoleID;
   HANDLE InputHandle;
   USHORT ImageNameSize;
   CHAR MessageBuffer[CONSOLE_READ_INFO_MESSAGE_BUFFER_SIZE];
   PVOID MessageBufferPtr;
   ULONG NumberOfCharsToRead;
   ULONG MessageBufferSize;
   ULONG Unknown1;
   ULONG Unknown2;
   ULONG Unknown3;
   BOOLEAN Unicode;
} CSR_CONSOLE_READ_INFORMATION, *PCSR_CONSOLE_READ_INFORMATION;

typedef struct _CSR_CONSOLE_WRITE_MESSAGE {
   PORT_MESSAGE PortMessage;
   CSRSS_MESSAGE CsrMessage;
   CSR_CONSOLE_WRITE_INFORMATION WriteInfo;
} CSR_CONSOLE_WRITE_MESSAGE, *PCSR_CONSOLE_WRITE_MESSAGE;

typedef struct _CSR_CONSOLE_READ_MESSAGE {
   PORT_MESSAGE PortMessage;
   CSRSS_MESSAGE CsrMessage;
   CSR_CONSOLE_READ_INFORMATION ReadInfo;
} CSR_CONSOLE_READ_MESSAGE, *PCSR_CONSOLE_READ_MESSAGE;


NTSYSAPI
NTSTATUS
NTAPI
ZwRequestWaitReplyPort(
   IN HANDLE PortHandle,
   IN PPORT_MESSAGE RequestMessage,
   OUT PPORT_MESSAGE ReplyMessage
);

typedef NTSTATUS (NTAPI *PZWREQUESTWAITREPLYPORT)(HANDLE, PPORT_MESSAGE, PPORT_MESSAGE);

NTSTATUS
NTAPI
ZwSecureConnectPort(
   OUT PHANDLE PortHandle,
   IN PUNICODE_STRING PortName,
   IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
   IN OUT PPORT_SECTION_WRITE WriteSection OPTIONAL,
   IN PSID ServerSid OPTIONAL,
   IN OUT PPORT_SECTION_READ ReadSection OPTIONAL,
   OUT PULONG MaxMessageSize OPTIONAL,
   IN OUT PVOID ConnectData OPTIONAL,
   IN OUT PULONG ConnectDataLength OPTIONAL
);

typedef NTSTATUS (NTAPI *PZWSECURECONNECTPORT)(PHANDLE, PUNICODE_STRING, 
                                               PSECURITY_QUALITY_OF_SERVICE, 
                                               PPORT_SECTION_WRITE, PSID, 
                                               PPORT_SECTION_READ, PULONG,
                                               PVOID, PULONG);

NTSTATUS
NTAPI
ZwCreateThread(
			   OUT PHANDLE ThreadHandle,
			   IN ACCESS_MASK DesiredAccess,
			   IN POBJECT_ATTRIBUTES ObjectAttributes,
			   IN HANDLE ProcessHandle,
			   OUT PCLIENT_ID ClientId,
			   IN PCONTEXT ThreadContext,
			   IN /*PUSER_STACK*/HANDLE UserStack,
			   IN BOOLEAN CreateSuspended
			   );

typedef NTSTATUS (NTAPI *PZWCREATETHREAD)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
										   HANDLE, PCLIENT_ID,
										   PCONTEXT, HANDLE,BOOLEAN);

typedef NTSTATUS (NTAPI *PZWCLOSE)(HANDLE);
typedef NTSTATUS (NTAPI *PZWWRITEFILE)(HANDLE, HANDLE,
																			 PIO_APC_ROUTINE, PVOID,
																			 PIO_STATUS_BLOCK, PVOID,
																			 ULONG, PLARGE_INTEGER,
																			 PULONG);

typedef NTSTATUS (NTAPI *PZWREADFILE)(HANDLE, HANDLE,
																			 PIO_APC_ROUTINE, PVOID,
																			 PIO_STATUS_BLOCK, PVOID,
																			 ULONG, PLARGE_INTEGER,
																			 PULONG);

//
// Port handle datastructure management
//
typedef struct _CSRSS_PORT_HANDLE_ENTRY {
   LIST_ENTRY ListEntry;
   ULONG ProcessId;
   HANDLE PortHandle;
   ULONG VirtualOffset;
} CSRSS_PORT_HANDLE_ENTRY, *PCSRSS_PORT_HANDLE_ENTRY;

static PCSRSS_PORT_HANDLE_ENTRY
GetCsrssHandleEntry(
   IN ULONG ProcessId,
   IN CONST HANDLE PortHandle
   );

static BOOLEAN 
IsCsrssPortHandle(
   IN ULONG ProcessId,
   IN HANDLE hPort
   );

static ULONG
GetVirtualOffsetFromHandle(
   IN ULONG ProcessId,
   IN HANDLE PortHandle
   );

static VOID
InsertCsrssPortHandle(
   IN ULONG ProcessId,
   IN HANDLE PortHandle,
   IN ULONG VirtualOffset
   );

static VOID
RemoveCsrssPortHandle(
   IN ULONG ProcessId,
   IN HANDLE PortHandle
   );


//
// Hooked functions
//
static
NTSTATUS 
NTAPI 
OnZwRequestWaitReplyPort(
   IN HANDLE PortHandle,
   IN PPORT_MESSAGE RequestMessage,
   OUT PPORT_MESSAGE ReplyMessage
   );

static
NTSTATUS
NTAPI
OnZwSecureConnectPort(
   OUT PHANDLE PortHandle,
   IN PUNICODE_STRING PortName,
   IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
   IN OUT PPORT_SECTION_WRITE WriteSection OPTIONAL,
   IN PSID ServerSid OPTIONAL,
   IN OUT PPORT_SECTION_READ ReadSection OPTIONAL,
   OUT PULONG MaxMessageSize OPTIONAL,
   IN OUT PVOID ConnectData OPTIONAL,
   IN OUT PULONG ConnectDataLength OPTIONAL
   );

static
NTSTATUS
NTAPI OnZwCreateProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ParentProcess,
	IN BOOLEAN InheritObjectTable,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL
);

static
NTSTATUS
NTAPI
OnZwClose(
   IN HANDLE Handle
   );

static
VOID
LogIfStdHandle(
		IN CONST HANDLE FileHandle,
		IN PVOID Buffer,
		IN ULONG Length
		);

static
NTSTATUS
NTAPI
OnZwReadFile(
    IN HANDLE  FileHandle,
    IN HANDLE  Event  OPTIONAL,
    IN PIO_APC_ROUTINE  ApcRoutine  OPTIONAL,
    IN PVOID  ApcContext  OPTIONAL,
    OUT PIO_STATUS_BLOCK  IoStatusBlock,
    OUT PVOID  Buffer,
    IN ULONG  Length,
    IN PLARGE_INTEGER  ByteOffset  OPTIONAL,
    IN PULONG  Key  OPTIONAL
    );

static
NTSTATUS
NTAPI
OnZwWriteFile(
    IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PVOID Buffer,
    IN ULONG Length,
    IN PLARGE_INTEGER ByteOffset OPTIONAL,
    IN PULONG Key OPTIONAL
    );

static
NTSTATUS
NTAPI
OnZwCreateThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN HANDLE ProcessHandle,
	OUT PCLIENT_ID ClientId,
	IN PCONTEXT ThreadContext,
	IN HANDLE UserStack,
	IN BOOLEAN CreateSuspended
	);

NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
    IN ULONG        ProcessId,
    OUT PEPROCESS   *Process
);

//
// Driver code specifics
//
static BOOLEAN s_ConsoleSpyInit = FALSE;

typedef void (__stdcall *PONCONSOLEIO)(const ProcessData *, const PANSI_STRING);

NTSTATUS InitConsoleSpy(PONCONSOLEIO fnWrite, PONCONSOLEIO fnRead);
NTSTATUS UninitConsoleSpy();
void OnConsoleWrite(const ProcessData *pProcessData, const PANSI_STRING str);
void OnConsoleRead(const ProcessData *pProcessData, const PANSI_STRING str);
BOOLEAN GetProcessInfo(ProcessData *pProcessData);
BOOLEAN FreeProcessData(ProcessData *pProcessData);
