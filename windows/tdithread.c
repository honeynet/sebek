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

#ifdef ENABLE_TDIHOOK
#include "TDIthread.h"
#include "sebek.h"
#include "exports.h"
#include "debug.h"
#include "logging.h"
#include "util.h"
#include "tdi_hook.h"

KEVENT g_TDIThreadShutdownEvent;
extern KEVENT g_TDIThreadStartEvent;
PDRIVER_OBJECT g_pTCPIPDriverObject = NULL;

VOID TDIThread(PVOID pData)
{
	PVOID eventArray[2];
	const ULONG ulNumEvents = sizeof(eventArray)/sizeof(eventArray[0]); 
	NTSTATUS status;
	LARGE_INTEGER liTimeout;
	UNICODE_STRING drv_name;
	ULONG ulTotalTime = 0;

	RtlInitUnicodeString(&drv_name, L"\\Driver\\Tcpip");

	// Start event is Initialized externally to avoid race conditions
	KeInitializeEvent(&g_TDIThreadShutdownEvent, NotificationEvent, FALSE);
	
  eventArray[0] = &g_TDIThreadShutdownEvent;
  eventArray[1] = &g_TDIThreadStartEvent;

	status = KeWaitForMultipleObjects(ulNumEvents, eventArray, WaitAny, Executive, KernelMode, FALSE, NULL, NULL);
	switch(status) {
		case 0: // Shutdown!
			PsTerminateSystemThread(STATUS_SUCCESS);
			return;
		case 1:
			break;
		default:	
			DBGOUT(("TDI Thread KeWaitForMultipleObjects failed! ErrorCode %08X", status));
			PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
			return;
	}
	

	// Timeouts are in units of 100 nanoseconds.
	// Negative timeout values are treated as relative time.
	liTimeout.QuadPart = (long)TDI_RETRY_TIMER * (1000 * 1000 * 10 * -1);

	DBGOUT(("TDI Thread Initialized! Will loop every %d seconds looking for TCPIP Driver", TDI_RETRY_TIMER));
	while(1) {
		status = KeWaitForSingleObject(&g_TDIThreadShutdownEvent, Executive, KernelMode, FALSE, &liTimeout);

		DBGOUT(("KeWaitForSingleObject returned 0x%08X", status));
		switch(status) {
			case 0: // Shutdown event!
thread_exit:
				PsTerminateSystemThread(STATUS_SUCCESS);
				return;
			case STATUS_TIMEOUT: // Data on our pipe
				{
					// See if TCPIP.sys is loaded yet:
					status = ObReferenceObjectByName(&drv_name, OBJ_CASE_INSENSITIVE, NULL, 0, IoDriverObjectType, KernelMode, NULL, &g_pTCPIPDriverObject);
					if(status == STATUS_SUCCESS) {
						DBGOUT(("TDI Driver Hooked!"));
						status = InitTDIHook();
						if(status != STATUS_SUCCESS)
							DBGOUT(("Unable to Initialize TDI Hook Driver!"));

						goto thread_exit;
					} else {
						DBGOUT(("Did not find TCPIP.sys driver. Going to sleep"));
						ulTotalTime += TDI_RETRY_TIMER;
						if(ulTotalTime < TDI_INIT_TIMEOUT)
							continue;
						else {
							// ERROR OUT
							DBGOUT(("Never found TCPIP Driver after %d seconds. Failing!!!", TDI_INIT_TIMEOUT));
							goto thread_exit;
						}
					}
				}
				break;
			default:
				DBGOUT(("Unknown status from KeWaitForSingleObject! Status: 0x%08X\n", status));
				goto thread_exit;
		}
	}
}
#endif