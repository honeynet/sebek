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

#include <ntddk.h>
#include "consolespy.h"
#include "sebek.h"
#include "logging.h"
#include "util.h"
#include "tib.h"
#include "memtrack.h"
#include "proc_tbl.h"

static PZWREQUESTWAITREPLYPORT s_fnZwRequestWaitReplyPort;
static PZWCLOSE s_fnZwClose;
static PZWSECURECONNECTPORT s_fnZwSecureConnectPort;
static PZWWRITEFILE s_fnZwWriteFile;
static PZWREADFILE s_fnZwReadFile;
static PZWCREATETHREAD s_fnZwCreateThread;

static PONCONSOLEIO s_fnOnConsoleWrite;
static PONCONSOLEIO s_fnOnConsoleRead;

static LIST_ENTRY s_PortHandleList;
static KSPIN_LOCK s_PortHandleListLock;
static BOOLEAN s_PortDataInitialized;

NPAGED_LOOKASIDE_LIST g_ConsoleNLookasideList;
NPAGED_LOOKASIDE_LIST g_GetProcessLookasideList;

NTSTATUS
InitConsoleSpy(PONCONSOLEIO fnWrite, PONCONSOLEIO fnRead)
{
#ifdef ENABLE_CONSOLESPY
	NTSTATUS status = STATUS_SUCCESS;

	status = proc_init();
	if(status) {
		DBGOUT(("InitConsoleSpy: proc_init: 0x%x\n", status));
		return STATUS_UNSUCCESSFUL;
	}

	s_fnOnConsoleWrite = fnWrite;
	s_fnOnConsoleRead = fnRead;

	InitializeListHead(&s_PortHandleList);
	KeInitializeSpinLock(&s_PortHandleListLock);

	s_PortDataInitialized = TRUE;

	ExInitializeNPagedLookasideList(&g_ConsoleNLookasideList, NULL, NULL, 0, sizeof(CSRSS_PORT_HANDLE_ENTRY), MEM_TAG, 0);
	ExInitializeNPagedLookasideList(&g_GetProcessLookasideList, NULL, NULL, 0, PROCESSDATA_MAX_LENGTH, MEM_TAG, 0);

	// Redirect syscalls
	if(!SetSystemCallIndex(SYSTEMSERVICE(ZwRequestWaitReplyPort), (PVOID)OnZwRequestWaitReplyPort, (PVOID*)&s_fnZwRequestWaitReplyPort))
		return STATUS_UNSUCCESSFUL;

	if(!SetSystemCallIndex(SYSTEMSERVICE(ZwClose), (PVOID)OnZwClose, (PVOID*)&s_fnZwClose))
		return STATUS_UNSUCCESSFUL;

	if(!SetSystemCallIndex(SYSCALL_INDEX_ZWSECURECONNECTPORT, (PVOID)OnZwSecureConnectPort, (PVOID*)&s_fnZwSecureConnectPort))
		return STATUS_UNSUCCESSFUL;

	if(!SetSystemCallIndex(SYSTEMSERVICE(ZwReadFile), OnZwReadFile, (PVOID *)&s_fnZwReadFile))
		return STATUS_UNSUCCESSFUL;

	if(!SetSystemCallIndex(SYSTEMSERVICE(ZwWriteFile), OnZwWriteFile, (PVOID *)&s_fnZwWriteFile))
		return STATUS_UNSUCCESSFUL;

	if(!SetSystemCallIndex(SYSCALL_INDEX_ZWCREATETHREAD, OnZwCreateThread, (PVOID *)&s_fnZwCreateThread))
		return STATUS_UNSUCCESSFUL;

	DBGOUT(("ConsoleSpy Initialized!\n"));
	s_ConsoleSpyInit = TRUE;
#endif
	return STATUS_SUCCESS;
}

NTSTATUS
UninitConsoleSpy()
   {
	if(!s_ConsoleSpyInit)
		return STATUS_SUCCESS;

	if(!SetSystemCallIndex(SYSTEMSERVICE(ZwRequestWaitReplyPort), s_fnZwRequestWaitReplyPort, NULL))
				return STATUS_UNSUCCESSFUL;

	if(!SetSystemCallIndex(SYSTEMSERVICE(ZwClose), (PVOID)s_fnZwClose, NULL))
				return STATUS_UNSUCCESSFUL;

	if(!SetSystemCallIndex(SYSCALL_INDEX_ZWSECURECONNECTPORT, (PVOID)s_fnZwSecureConnectPort, NULL))
				return STATUS_UNSUCCESSFUL;

			if(!SetSystemCallIndex(SYSTEMSERVICE(ZwReadFile), (PVOID)s_fnZwReadFile, NULL))
				return STATUS_UNSUCCESSFUL;

			if(!SetSystemCallIndex(SYSTEMSERVICE(ZwWriteFile), (PVOID)s_fnZwWriteFile, NULL))
				return STATUS_UNSUCCESSFUL;

	if(!SetSystemCallIndex(SYSCALL_INDEX_ZWCREATETHREAD, (PVOID)s_fnZwCreateThread, NULL))
		return STATUS_UNSUCCESSFUL;

	ExDeleteNPagedLookasideList(&g_ConsoleNLookasideList);
	ExDeleteNPagedLookasideList(&g_GetProcessLookasideList);

	s_ConsoleSpyInit = FALSE;

	proc_free();
	 return STATUS_SUCCESS;
}

BOOLEAN GetProcessInfo(ProcessData *pProcessData)
{
	EPROCESS *pEProcess = NULL;
	NTSTATUS status;
	UNICODE_STRING p;
	
	if(KeGetCurrentIrql() > DISPATCH_LEVEL) {
		DBGOUT(("GetProcessInfo: IRQL too high. IRQL: %d", KeGetCurrentIrql()));
		return FALSE;
	}

	if(!pProcessData)
		return FALSE;

	status = PsLookupProcessByProcessId(pProcessData->ulProcessID, (PEPROCESS *)&pEProcess);
	if(!NT_SUCCESS(status)) {
		DBGOUT(("GetProcessInfo: PsLookupProcessByProcessId Failed: %08X", status));
		return FALSE;
	}

	if(!pEProcess) {
		DBGOUT(("GetProcessInfo: pEProcess is null!"));
		return FALSE;
	}

	pProcessData->ulParentPID = pEProcess->InheritedFromUniqueProcessId;
#if DBG
	if(pProcessData->ulParentPID == 0)
		DBGOUT(("PID %d has a Parent PID of 0!", pProcessData->ulProcessID));

	if(pProcessData->ulProcessID == 0)
		DBGOUT(("Process has a PID of 0!"));
#endif

	RtlZeroMemory(&pProcessData->usProcessName, sizeof(UNICODE_STRING));
	RtlZeroMemory(&pProcessData->usWindowTitle, sizeof(UNICODE_STRING));
	RtlZeroMemory(&pProcessData->usUsername, sizeof(UNICODE_STRING));

	if(!pEProcess->Peb) {
		DBGOUT(("GetProcessInfo: pEProcess->Peb is null!"));
		return FALSE;
	} else {
		if(!pEProcess->Peb->ProcessParameters) {
			DBGOUT(("GetProcessInfo: pEPRocess->Peb->ProcessParameters is null!"));
			return FALSE;
		}

		pProcessData->usWindowTitle.MaximumLength = min(pEProcess->Peb->ProcessParameters->WindowTitle.Length + sizeof(WCHAR), PROCESSDATA_MAX_LENGTH - sizeof(WCHAR));
		//pProcessData->usWindowTitle.Buffer = (WCHAR *)ExAllocatePool(PagedPool, pProcessData->usWindowTitle.MaximumLength+  sizeof(WCHAR));
		pProcessData->usWindowTitle.Buffer = (PWSTR)ExAllocateFromNPagedLookasideList(&g_GetProcessLookasideList);
		RtlZeroMemory(pProcessData->usWindowTitle.Buffer, pProcessData->usWindowTitle.MaximumLength);
		RtlCopyUnicodeString(&pProcessData->usWindowTitle, &pEProcess->Peb->ProcessParameters->WindowTitle);

		// We only want the filename of the exe not the full path
		p.Buffer = wcsrchr(pEProcess->Peb->ProcessParameters->ImagePathName.Buffer, '\\') + 1;
		p.MaximumLength = p.Length = wcslen(p.Buffer) * sizeof(WCHAR);
		pProcessData->usProcessName.MaximumLength = min(p.Length + sizeof(WCHAR), PROCESSDATA_MAX_LENGTH - sizeof(WCHAR));
		pProcessData->usProcessName.Buffer = (PWSTR)ExAllocateFromNPagedLookasideList(&g_GetProcessLookasideList);
		RtlZeroMemory(pProcessData->usProcessName.Buffer, pProcessData->usProcessName.MaximumLength);
		RtlCopyUnicodeString(&pProcessData->usProcessName, &p);

		pProcessData->usUsername.MaximumLength = PROCESSDATA_MAX_LENGTH - sizeof(WCHAR);
		pProcessData->usUsername.Length = 0;
		pProcessData->usUsername.Buffer = (PWSTR)ExAllocateFromNPagedLookasideList(&g_GetProcessLookasideList);
		RtlZeroMemory(pProcessData->usUsername.Buffer, pProcessData->usUsername.MaximumLength + sizeof(WCHAR));

		if(!GetUserSIDFromProcess(pEProcess, &pProcessData->usUsername)) {
			DBGOUT(("GetProcessInfo: Unable to get UserSID From Process!"));
			ExFreeToNPagedLookasideList(&g_GetProcessLookasideList, pProcessData->usWindowTitle.Buffer);
			ExFreeToNPagedLookasideList(&g_GetProcessLookasideList, pProcessData->usProcessName.Buffer);
			RtlZeroMemory(&pProcessData->usProcessName, sizeof(UNICODE_STRING));
			RtlZeroMemory(&pProcessData->usWindowTitle, sizeof(UNICODE_STRING));
			RtlZeroMemory(&pProcessData->usUsername, sizeof(UNICODE_STRING));
			return FALSE;
		}
	}
	
	//DBGOUT(("GetProcessInfo: ProcName: %S UserName: %S WindowTitle: %S PID: %d", pProcessData->usProcessName.Buffer, pProcessData->usUsername.Buffer, pProcessData->usWindowTitle.Buffer, pProcessData->ulParentPID));
	return TRUE;
}

void
OnConsoleWrite(const ProcessData *pProcessData, const PANSI_STRING str)
{
	if(!str)
		return;

	DBGOUT(("OnConsoleWrite(): %d bytes read -> '%s'\n", str->Length, str->Buffer));
	LogData(SEBEK_TYPE_READ, pProcessData, str->Buffer, str->Length);
}

void
OnConsoleRead(const ProcessData *pProcessData, const PANSI_STRING str)
{
	if(!str)
		return;

	DBGOUT(("OnConsoleRead(): %d bytes read -> '%s'\n", str->Length, str->Buffer));
	LogData(SEBEK_TYPE_READ, pProcessData, str->Buffer, str->Length);
}


// ----------------------
// Special Event Handlers
//
static void
OnCsrWriteDataPre(const ProcessData *pProcessData, const PCSR_CONSOLE_WRITE_MESSAGE Message, const ULONG VirtualOffset)
{
   PVOID WriteStringPtr = 0;
   USHORT cbSize = 0;
   ANSI_STRING as;

	 if(!Message)
		 return;

   //
   // Is the buffer inline with the Message?
   //
   __try
   {
      if (Message->WriteInfo.MessageBufferPtr != Message->WriteInfo.MessageBuffer)
      {
         PUCHAR Offset;

         //
         // Nope - Let's translate the address into something usable and verifiable
         //
         Offset = (PUCHAR)((ULONG)Message->WriteInfo.MessageBufferPtr - VirtualOffset);
         if (MmIsAddressValid((PVOID)Offset) && 
            MmIsAddressValid((PVOID)(&Offset[Message->WriteInfo.MessageBufferSize])))
         {
            WriteStringPtr = (PVOID)Offset;
            cbSize = (USHORT)Message->WriteInfo.MessageBufferSize;
         }
      }
      else
      {
         WriteStringPtr = (PVOID)Message->WriteInfo.MessageBuffer;
         cbSize = (USHORT)(min(Message->WriteInfo.MessageBufferSize, CONSOLE_WRITE_INFO_MESSAGE_BUFFER_SIZE));
      }

      if (!WriteStringPtr) // bad data
         return;

      if (Message->WriteInfo.Unicode)
      {
         UNICODE_STRING us;

         us.Buffer = (wchar_t*)WriteStringPtr;
         us.Length = cbSize;
         us.MaximumLength = cbSize;

         RtlUnicodeStringToAnsiString(&as, &us, TRUE);
      }
      else
      {
         as.Length = (USHORT)Message->WriteInfo.MessageBufferSize;
         as.MaximumLength = (USHORT)Message->WriteInfo.MessageBufferSize;
         as.Buffer = (char*)WriteStringPtr;
      }

      if (s_fnOnConsoleWrite)
         s_fnOnConsoleWrite(pProcessData, &as);

      // free allocated ansi buffer if needed
      if (Message->WriteInfo.Unicode)
         RtlFreeAnsiString(&as);

   } __except(EXCEPTION_EXECUTE_HANDLER)
   {
   }
}

static void
OnCsrReadDataPost(const ProcessData *pProcessData, const PCSR_CONSOLE_READ_MESSAGE Message, const ULONG VirtualOffset)
{
   PVOID ReadStringPtr = 0;
   ANSI_STRING as;

	 if(!Message)
		 return;

   //
   // Is the buffer inline with the Message?
   //
   __try
   {
      if (Message->ReadInfo.MessageBufferPtr != Message->ReadInfo.MessageBuffer)
      {
         PUCHAR Offset;

         //
         // Nope - Let's translate the address into something usable and verifiable
         //
         Offset = (PUCHAR)((ULONG)Message->ReadInfo.MessageBufferPtr - VirtualOffset);
         if (MmIsAddressValid((PVOID)Offset) && 
            MmIsAddressValid((PVOID)(&Offset[Message->ReadInfo.MessageBufferSize])))
         {
            ReadStringPtr = (PVOID)Offset;
         }
      }
      else
      {
         ReadStringPtr = (PVOID)Message->ReadInfo.MessageBuffer;
      }

      if (!ReadStringPtr) // bad data
         return;

      if (Message->ReadInfo.Unicode)
      {
         UNICODE_STRING us;

         us.Buffer = (wchar_t*)ReadStringPtr;
         us.Length = (USHORT)Message->ReadInfo.NumberOfCharsToRead;
         us.MaximumLength = (USHORT)Message->ReadInfo.NumberOfCharsToRead;

         RtlUnicodeStringToAnsiString(&as, &us, TRUE);
      }
      else
      {
         as.Length = (USHORT)Message->ReadInfo.NumberOfCharsToRead;
         as.MaximumLength = (USHORT)Message->ReadInfo.NumberOfCharsToRead;
         as.Buffer = (char*)ReadStringPtr;
      }

      if (s_fnOnConsoleRead)
         s_fnOnConsoleRead(pProcessData, &as);

      // free allocated ansi buffer if needed
      if (Message->ReadInfo.Unicode)
         RtlFreeAnsiString(&as);

   } __except(EXCEPTION_EXECUTE_HANDLER)
   {
   }
}

// Currently not needed.
#define OnCsrWriteDataPost(x, y, z) ;
#define OnCsrReadDataPre(x, y, z) ;

// ----------------
// Hooked Syscalls
//
static
NTSTATUS 
NTAPI 
OnZwRequestWaitReplyPort(
   IN HANDLE PortHandle,
   IN PPORT_MESSAGE RequestMessage,
   OUT PPORT_MESSAGE ReplyMessage
   )
{
   NTSTATUS status;
   BOOLEAN bDiscard;
	ProcessData ProcInfo;
	RtlZeroMemory(&ProcInfo, sizeof(ProcInfo));
	ProcInfo.ulProcessID = (ULONG)PsGetCurrentProcessId();
	 
	 bDiscard = TRUE; 
   
   InterlockedIncrement((PLONG)&s_ulCallCount);

	if(RequestMessage != NULL && IsCsrssPortHandle(ProcInfo.ulProcessID, PortHandle))
   {
		PCSRSS_MESSAGE pCsrMsg = NULL;
		ULONG VirtualOffset = 0;
      
		// What should we do about this process?
		// Get the Process info
		if(!GetProcessInfo(&ProcInfo)) {
			DBGOUT(("OnZwRequestWaitReplyPort: Unable to get ProcessInfo!"));
			bDiscard = TRUE;
			goto discard;
		}

		pCsrMsg = (PCSRSS_MESSAGE)((PPORT_MESSAGE)RequestMessage + 1); 
		VirtualOffset = GetVirtualOffsetFromHandle(ProcInfo.ulProcessID, PortHandle);

      if (pCsrMsg->OpCode == OPCODE_WRITE_CONSOLE)
      {
         PCSR_CONSOLE_WRITE_MESSAGE pWriteMsg = (PCSR_CONSOLE_WRITE_MESSAGE)RequestMessage;
         
				OnCsrWriteDataPre(&ProcInfo, pWriteMsg, VirtualOffset);
         status = s_fnZwRequestWaitReplyPort(PortHandle, RequestMessage, ReplyMessage);
				OnCsrWriteDataPost(&ProcInfo, pWriteMsg, VirtualOffset);
         
         bDiscard = FALSE;
      }
      else if (pCsrMsg->OpCode == OPCODE_READ_CONSOLE)
      {
         PCSR_CONSOLE_READ_MESSAGE pReadMsg = (PCSR_CONSOLE_READ_MESSAGE)RequestMessage;
         
				OnCsrReadDataPre(&ProcInfo, pReadMsg, VirtualOffset);
         status = s_fnZwRequestWaitReplyPort(PortHandle, RequestMessage, ReplyMessage);
				OnCsrReadDataPost(&ProcInfo, pReadMsg, VirtualOffset);

         bDiscard = FALSE;
      }
   }

discard:
   if (bDiscard)
      status = s_fnZwRequestWaitReplyPort(PortHandle, RequestMessage, ReplyMessage);
   
   InterlockedDecrement((PLONG)&s_ulCallCount);

	FreeProcessData(&ProcInfo);
	
   return status;
}


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
   )
{
   NTSTATUS status;
   
   InterlockedIncrement((PLONG)&s_ulCallCount);

   status = s_fnZwSecureConnectPort(PortHandle, PortName, SecurityQos, WriteSection, 
      ServerSid, ReadSection, MaxMessageSize, ConnectData, ConnectDataLength);

   if (NT_SUCCESS(status))
   {
      if(PortName != NULL && MmIsAddressValid(PortName) 
				&& PortName->Buffer != NULL && MmIsAddressValid(PortName->Buffer) 
				&& WriteSection != NULL && MmIsAddressValid(WriteSection))
      {
         if (wcsncmp(PortName->Buffer, L"\\Windows\\ApiPort", PortName->Length / sizeof(WCHAR)) == 0)
         {
            ULONG VirtualOffset = (ULONG)WriteSection->TargetViewBase - (ULONG)WriteSection->ViewBase;
						//lint -e613
            InsertCsrssPortHandle((ULONG)PsGetCurrentProcessId(), (HANDLE)(*((PULONG)PortHandle)), VirtualOffset);
         }
      }
   }


   InterlockedDecrement((PLONG)&s_ulCallCount);

   return status;
}

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
)
{
	NTSTATUS status;

	InterlockedIncrement((PLONG)&s_ulCallCount);

	status = s_fnZwCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, UserStack, CreateSuspended);

	if (NT_SUCCESS(status)) {
		ProcessData *pProcInfo;
		proc_entry_t *pProcEntry;
		TIME liCurrentTime;
		KIRQL irql;

		// Search for this process
		pProcEntry = proc_find((ULONG)PsGetCurrentProcessId(), &irql);
		if(!pProcEntry) {
			pProcInfo = (ProcessData *)malloc_np(sizeof(ProcessData));
			pProcInfo->ulProcessID = (ULONG)PsGetCurrentProcessId();
			// What should we do about this process?
			// Get the Process info
			if(!GetProcessInfo(pProcInfo)) {
				DBGOUT(("OnZwCreateThread: Unable to get ProcessInfo!"));
				FreeProcessData(pProcInfo);
				goto done;
			}

		} else {
			pProcInfo = (ProcessData *)pProcEntry->pProcInfo;
			KeReleaseSpinLock(&g_proc_hash_guard, irql);
		}

		DBGOUT(("OnZwCreateThread: ProcessID %d", pProcInfo->ulProcessID));

		// Add this to our list of process info
		KeQuerySystemTime(&liCurrentTime);
		if(!NT_SUCCESS(proc_add(pProcInfo->ulProcessID, pProcInfo, liCurrentTime))) {
			if(!pProcEntry)
				FreeProcessData(pProcInfo);
			goto done;
		}

		LogData(SEBEK_TYPE_READ, pProcInfo, NULL, 0);
	}

done:
	InterlockedDecrement((PLONG)&s_ulCallCount);

	return status;
}

static
NTSTATUS
NTAPI
OnZwClose(
   IN HANDLE Handle
   )
{
   NTSTATUS status;
   
   InterlockedIncrement((PLONG)&s_ulCallCount);

   if (IsCsrssPortHandle((ULONG)PsGetCurrentProcessId(), Handle))
      RemoveCsrssPortHandle((ULONG)PsGetCurrentProcessId(), Handle);

   status = s_fnZwClose(Handle);

   InterlockedDecrement((PLONG)&s_ulCallCount);

   return status;
}

/*
 *	Ok, a little documentation on how LogIfStdHandle works.
 *
 *	First, we retrieve the address of the TIB for the thread calling this function.
 *	This should be from a hooked service sucha s ZwReadFile and ZwWriteFile.
 *	Then we get the address of the PEB, and then the Environment block inside the PEB.
 *	The Environment block contains HANDLEs to STDIN, STDOUT, and STDERR.
 *
 *	We check to see if the WriteFile is attempting to write to one of those handles.
 *	If WriteFile is attempting to write to one of those handles then the process was passed
 *	a HANDLE instead of using the standard console subsystem pseudo handles.
 *
 *	This should catch any exploits which pass a socket or file directly to CreateProcess().
 */
static VOID
LogIfStdHandle(
		IN CONST HANDLE FileHandle,
		IN PVOID Buffer,
		IN ULONG Length
		)
{
	PTIB pTIB = NULL;

	/*
	 *	Check that the call is from UserMode and double check we are not being called
	 *	at too high of an IRQL.
	 */
	if(ExGetPreviousMode() == UserMode && KeGetCurrentIrql() < DISPATCH_LEVEL) {
		__asm
    {
        mov     EAX, FS:[18h]		; Store TIB in 32bit register so we don't have to mess with segments.
				mov     [pTIB], EAX			; Push the address into our pointer
    }

		//lint -e774
		if(pTIB) {
			if(pTIB->pPEB && pTIB->pPEB->ProcessParameters) {
				if(FileHandle == pTIB->pPEB->ProcessParameters->StandardOutput || FileHandle == pTIB->pPEB->ProcessParameters->StandardInput || FileHandle == pTIB->pPEB->ProcessParameters->StandardError) {
					ANSI_STRING asDest;
					ProcessData ProcInfo;
					asDest.Buffer = (PCHAR)Buffer;
					asDest.Length = (USHORT)Length;
					asDest.MaximumLength = (USHORT)Length;

					RtlZeroMemory(&ProcInfo, sizeof(ProcInfo));
					ProcInfo.ulProcessID = pTIB->processID;

					// What should we do about this process?
					// Get the Process info
					if(!GetProcessInfo(&ProcInfo))
						return;

					OnConsoleRead(&ProcInfo, &asDest);
					FreeProcessData(&ProcInfo);
				}
			}
		}
	}
}


/*
 *	Read above documentation for LogIfStdHandle on how this function works.
 */
static NTSTATUS
NTAPI
OnZwReadFile(
  	IN HANDLE FileHandle,
		IN HANDLE Event OPTIONAL,
		IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
		IN PVOID ApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		IN PVOID Buffer,
		IN ULONG Length,
		IN PLARGE_INTEGER ByteOffset OPTIONAL,
		IN PULONG Key OPTIONAL
		)
{
	NTSTATUS status;
	
	InterlockedIncrement((PLONG)&s_ulCallCount);

	status = s_fnZwReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);

	if(status == STATUS_SUCCESS) 
		LogIfStdHandle(FileHandle, Buffer, Length);

	InterlockedDecrement((PLONG)&s_ulCallCount);

	return status;
}

/*
 *	Read above documentation for LogIfStdHandle on how this function works.
 */
static NTSTATUS
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
		)
{
	NTSTATUS status;
	
	InterlockedIncrement((PLONG)&s_ulCallCount);

	status = s_fnZwWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);

	if(status == STATUS_SUCCESS) 
		LogIfStdHandle(FileHandle, Buffer, Length);

	InterlockedDecrement((PLONG)&s_ulCallCount);

	return status;
}

// -------------------------------------
// Port Handle Data Structure Management
//
static 
PCSRSS_PORT_HANDLE_ENTRY
GetCsrssHandleEntry(
   IN ULONG ProcessId,
   IN CONST HANDLE PortHandle
   )
{
   if (!IsListEmpty(&s_PortHandleList))
   {
      PCSRSS_PORT_HANDLE_ENTRY pCurEntry = 0;

      pCurEntry = (PCSRSS_PORT_HANDLE_ENTRY)s_PortHandleList.Flink;
      do
      {
         if (pCurEntry->ProcessId == ProcessId && pCurEntry->PortHandle == PortHandle)
            return pCurEntry;

         pCurEntry = (PCSRSS_PORT_HANDLE_ENTRY)pCurEntry->ListEntry.Flink;

      } while (pCurEntry != (PCSRSS_PORT_HANDLE_ENTRY)&s_PortHandleList);
   }

   return 0;
}

static ULONG
GetVirtualOffsetFromHandle(
   IN ULONG ProcessId,
   IN HANDLE PortHandle
   )
{
   KIRQL Irql;
   ULONG VirtualOffset = 0;
   PCSRSS_PORT_HANDLE_ENTRY Entry;

   if (!s_PortDataInitialized)
      return FALSE;

   KeAcquireSpinLock(&s_PortHandleListLock, &Irql);
   
   Entry = GetCsrssHandleEntry(ProcessId, PortHandle);
   if (Entry)
      VirtualOffset = Entry->VirtualOffset;

   KeReleaseSpinLock(&s_PortHandleListLock, Irql);

   return VirtualOffset;
}


static BOOLEAN 
IsCsrssPortHandle(
   IN ULONG ProcessId,
   IN HANDLE PortHandle
   )
{
   KIRQL Irql;
   BOOLEAN bCsrssHandle = FALSE;
   PCSRSS_PORT_HANDLE_ENTRY Entry;

   if (!s_PortDataInitialized)
      return FALSE;

   KeAcquireSpinLock(&s_PortHandleListLock, &Irql);
   
   Entry = GetCsrssHandleEntry(ProcessId, PortHandle);
   if (Entry)
      bCsrssHandle = TRUE;

   KeReleaseSpinLock(&s_PortHandleListLock, Irql);

   return bCsrssHandle;
}


static VOID
InsertCsrssPortHandle(
   IN ULONG ProcessId,
   IN HANDLE PortHandle,
   IN ULONG VirtualOffset
   )
{
   PCSRSS_PORT_HANDLE_ENTRY Entry;
   KIRQL Irql;

   if (!s_PortDataInitialized)
      return;

   Entry = (PCSRSS_PORT_HANDLE_ENTRY)ExAllocateFromNPagedLookasideList(&g_ConsoleNLookasideList);

   if (!Entry)
      return;

   DBGOUT(("InsertCsrssPortHandle(PID:%d; PortHandle:%xh; Offset:0x%08x\n", 
      ProcessId, PortHandle, VirtualOffset));

   Entry->PortHandle = PortHandle;
   Entry->ProcessId = ProcessId;
   Entry->VirtualOffset = VirtualOffset;

   KeAcquireSpinLock(&s_PortHandleListLock, &Irql);
   InsertHeadList(&s_PortHandleList, &Entry->ListEntry);
   KeReleaseSpinLock(&s_PortHandleListLock, Irql);
}


static VOID
RemoveCsrssPortHandle(
   IN ULONG ProcessId,
   IN HANDLE PortHandle
   )
{
   PCSRSS_PORT_HANDLE_ENTRY Entry;
   KIRQL Irql;

   if (!s_PortDataInitialized)
      return;

   KeAcquireSpinLock(&s_PortHandleListLock, &Irql);

   Entry = GetCsrssHandleEntry(ProcessId, PortHandle);

   if (Entry)
   {
      DBGOUT(("RemoveCsrssPortHandle(PID:%d; PortHandle:%xh\n", ProcessId, PortHandle));

      RemoveEntryList(&Entry->ListEntry);
      ExFreeToNPagedLookasideList(&g_ConsoleNLookasideList, Entry);
   }
   
   KeReleaseSpinLock(&s_PortHandleListLock, Irql);
}
