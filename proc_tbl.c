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

#include <ntddk.h>
#include <tdikrnl.h>
#include "memtrack.h"
#include "proc_tbl.h"
#include "debug.h"
#include "util.h"
#include "consolespy.h"

#define HASH_SIZE	0x0800
#define CALC_HASH(x)  ((x) & (HASH_SIZE-1))

static proc_entry_t **g_proc_hash;
KSPIN_LOCK g_proc_hash_guard;

//----------------------------------------------------------------------------

NTSTATUS proc_init(void)
{
	g_proc_hash = (proc_entry_t **)malloc_np(sizeof(*g_proc_hash) * HASH_SIZE);
	if (!g_proc_hash) {
		return STATUS_NO_MEMORY;
	}
	RtlZeroMemory(g_proc_hash, sizeof(*g_proc_hash) * HASH_SIZE);

	KeInitializeSpinLock(&g_proc_hash_guard);

	return STATUS_SUCCESS;
}

void proc_free(void)
{
	KIRQL irql;
	int i;

	if (g_proc_hash) {

		KeAcquireSpinLock(&g_proc_hash_guard, &irql);
		
		for (i = 0; i < HASH_SIZE; i++) {
			proc_entry_t *ote = g_proc_hash[i];
			while (ote) {
				proc_entry_t *ote2 = ote->next;
				int j;

				FreeProcessData((ProcessData *)ote->pProcInfo);
				free((ProcessData *)ote->pProcInfo);
				free(ote);
				ote = ote2;
			}
		}
		free(g_proc_hash); g_proc_hash = NULL;

		KeReleaseSpinLock(&g_proc_hash_guard, irql);
	}
}

void RemoveUnseenProcesses(void)
{
	KIRQL irql;
	int i;
	TIME liCurrentTime;

	if (g_proc_hash) {
		KeAcquireSpinLock(&g_proc_hash_guard, &irql);
		KeQuerySystemTime(&liCurrentTime);

		for (i = 0; i < HASH_SIZE; i++) {
			proc_entry_t *ote = g_proc_hash[i];
			while (ote) {
				proc_entry_t *ote2 = ote->next;

				if(RtlLargeIntegerLessThan(liCurrentTime, ote->lastseen)) {
					FreeProcessData((ProcessData *)ote->pProcInfo);
					free((ProcessData *)ote->pProcInfo);
					free(ote);
					ote = ote2;
				} else
					ote = ote->next;
			}
		}

		KeReleaseSpinLock(&g_proc_hash_guard, irql);
	}
}

//----------------------------------------------------------------------------

NTSTATUS proc_add(CONST ULONG pid, CONST ProcessData *pProcInfo, CONST TIME seen)
{
	ULONG hash = CALC_HASH(pid);
	KIRQL irql;
	proc_entry_t *ote, *old_next;
	NTSTATUS status;
	int i;

	KeAcquireSpinLock(&g_proc_hash_guard, &irql);
	
	for (ote = g_proc_hash[hash]; ote; ote = ote->next)
		if (ote->pid == pid) break;

	if (!ote) {
		ote = (proc_entry_t *)malloc_np(sizeof(*ote));
		if (!ote) {
			status = STATUS_NO_MEMORY;
			goto done;
		}
		memset(ote, 0, sizeof(*ote));

		ote->next = g_proc_hash[hash];
		g_proc_hash[hash] = ote;

		ote->pid = pid;
	} else {
		struct proc_entry *saved_next;
		ULONG saved_pid;

		DBGOUT(("proc_add: reuse pid 0x%x\n", pid));

		// set all fields to zero except "next" and "fileobj" (cleanup listen/conn_entry if any)

		saved_next = ote->next;
		saved_pid = ote->pid;

		memset(ote, 0, sizeof(*ote));

		ote->next = saved_next;
		ote->pid = saved_pid;
	}

	ote->lastseen = seen;
	ote->pProcInfo = pProcInfo;
	status = STATUS_SUCCESS;
done:

	KeReleaseSpinLock(&g_proc_hash_guard, irql);
	RemoveUnseenProcesses();
	return status;
}

NTSTATUS proc_del(CONST ULONG pid)
{
	ULONG hash = CALC_HASH(pid);
	KIRQL irql;
	proc_entry_t *ote, *prev_ote;
	NTSTATUS status;

	KeAcquireSpinLock(&g_proc_hash_guard, &irql);

	prev_ote = NULL;
	for (ote = g_proc_hash[hash]; ote; ote = ote->next) {
		if (ote->pid == pid) break;
		prev_ote = ote;
	}

	if (!ote) {
		status = STATUS_OBJECT_NAME_NOT_FOUND;
		goto done;
	}

	if (prev_ote) prev_ote->next = ote->next; else g_proc_hash[hash] = ote->next;
	
	FreeProcessData((ProcessData *)ote->pProcInfo);
	free((ProcessData *)ote->pProcInfo);
	free(ote);
	status = STATUS_SUCCESS;
done:

	KeReleaseSpinLock(&g_proc_hash_guard, irql);
	return status;
}

proc_entry_t *proc_find(CONST ULONG pid, KIRQL *irql)
{
	ULONG hash = CALC_HASH(pid);
	proc_entry_t *ote;
	NTSTATUS status;

	if (irql) KeAcquireSpinLock(&g_proc_hash_guard, irql);

	for (ote = g_proc_hash[hash]; ote; ote = ote->next)
		if (ote->pid == pid) break;

	if (!ote) {
		if (irql) KeReleaseSpinLock(&g_proc_hash_guard, *irql);
	}

	return ote;
}