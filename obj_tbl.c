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
#include "obj_tbl.h"
#include "debug.h"
#include "util.h"

#define HASH_SIZE	0x1000
#define CALC_HASH(fileobj)  (((ULONG)(fileobj) >> 5) % HASH_SIZE)

static ot_entry_t **g_ot_hash;
KSPIN_LOCK g_ot_hash_guard;

typedef struct ctx_entry {
	struct ctx_entry *next;
	PFILE_OBJECT addrobj;
	CONNECTION_CONTEXT conn_ctx;
	PFILE_OBJECT connobj;
} ctx_entry_t;

static ctx_entry_t **g_cte_hash;
KSPIN_LOCK g_cte_hash_guard;

static NTSTATUS do_set_old_event_handler(ot_entry_t *ote, int event_type);

//----------------------------------------------------------------------------

NTSTATUS ot_init(void)
{
	g_ot_hash = (ot_entry_t **)malloc_np(sizeof(*g_ot_hash) * HASH_SIZE);
	if (!g_ot_hash) {
		return STATUS_NO_MEMORY;
	}
	RtlZeroMemory(g_ot_hash, sizeof(*g_ot_hash) * HASH_SIZE);

	KeInitializeSpinLock(&g_ot_hash_guard);

	g_cte_hash = (ctx_entry_t **)malloc_np(sizeof(*g_cte_hash) * HASH_SIZE);
	if (!g_cte_hash) {
		free(g_ot_hash);
		return STATUS_NO_MEMORY;
	}
	memset(g_cte_hash, 0, sizeof(*g_cte_hash) * HASH_SIZE);

	KeInitializeSpinLock(&g_cte_hash_guard);

	return STATUS_SUCCESS;
}

void ot_free(void)
{
	KIRQL irql;
	int i;

	if (g_ot_hash) {

		KeAcquireSpinLock(&g_ot_hash_guard, &irql);
		
		for (i = 0; i < HASH_SIZE; i++) {
			ot_entry_t *ote = g_ot_hash[i];
			while (ote) {
				ot_entry_t *ote2 = ote->next;
				int j;
			
				if (ote->signature != 'OTE ')
					DBGOUT(("ot_free: Warning! fileobj 0x%x invalid signature 0x%x!\n", ote->fileobj, ote->signature));

				for (j = 0; j < MAX_EVENT; j++)
					if (ote->ctx[j].old_handler) do_set_old_event_handler(ote, j);

				free(ote);
				ote = ote2;
			}
		}
		free(g_ot_hash); g_ot_hash = NULL;

		KeReleaseSpinLock(&g_ot_hash_guard, irql);
	}

	if (g_cte_hash) {
		KeAcquireSpinLock(&g_cte_hash_guard, &irql);
		
		for (i = 0; i < HASH_SIZE; i++) {
			ctx_entry_t *cte = g_cte_hash[i];
			while (cte) {
				ctx_entry_t *cte2 = cte->next;
				free(cte);
				cte = cte2;
			}
		}
		free(g_cte_hash); g_cte_hash = NULL;

		KeReleaseSpinLock(&g_cte_hash_guard, irql);
	}
}

//----------------------------------------------------------------------------

NTSTATUS ot_add_fileobj(PDEVICE_OBJECT devobj, PFILE_OBJECT fileobj, int fileobj_type,
						CONNECTION_CONTEXT conn_ctx)
{
	ULONG hash = CALC_HASH(fileobj);
	KIRQL irql;
	ot_entry_t *ote, *old_next;
	NTSTATUS status;
	int i;

	if(!fileobj) 
		return STATUS_INVALID_PARAMETER_2;

	KeAcquireSpinLock(&g_ot_hash_guard, &irql);
	
	for (ote = g_ot_hash[hash]; ote; ote = ote->next)
		if (ote->fileobj == fileobj) break;

	if (!ote) {
		ote = (ot_entry_t *)malloc_np(sizeof(*ote));
		if (!ote) {
			status = STATUS_NO_MEMORY;
			goto done;
		}
		memset(ote, 0, sizeof(*ote));

		datapipe_init(&ote->in_oob_pipe);
		datapipe_init(&ote->in_pipe);
	
		ote->next = g_ot_hash[hash];
		g_ot_hash[hash] = ote;

		ote->fileobj = fileobj;
		for (i = 0; i < MAX_EVENT; i++) 
			ote->ctx[i].fileobj = fileobj;
	} else {
		struct ot_entry *saved_next;
		PFILE_OBJECT saved_fileobj;
		unsigned int i;

		DBGOUT(("ot_add_fileobj: reuse fileobj 0x%x\n", fileobj));

		// set all fields to zero except "next" and "fileobj" (cleanup listen/conn_entry if any)

		saved_next = ote->next;
		saved_fileobj = ote->fileobj;

		memset(ote, 0, sizeof(*ote));

		ote->next = saved_next;
		ote->fileobj = saved_fileobj;

		// restore fileobjs
		for (i = 0; i < MAX_EVENT; i++)
			ote->ctx[i].fileobj = saved_fileobj;
	}

	ote->pid = (ULONG)PsGetCurrentProcessId();
	memset(ote->ProcessName, 0, sizeof(ote->ProcessName));
	GetProcessName(ote->ProcessName);
	ote->signature = 'OTE ';
	ote->devobj = devobj;

	ote->type = fileobj_type;
	ote->conn_ctx = conn_ctx;
	
	status = STATUS_SUCCESS;
done:

	KeReleaseSpinLock(&g_ot_hash_guard, irql);
	return status;
}

NTSTATUS ot_del_fileobj(PFILE_OBJECT fileobj, int *fileobj_type)
{
	ULONG hash = CALC_HASH(fileobj);
	KIRQL irql;
	ot_entry_t *ote, *prev_ote;
	NTSTATUS status;

	if (!fileobj) return STATUS_INVALID_PARAMETER_1;

	KeAcquireSpinLock(&g_ot_hash_guard, &irql);

	prev_ote = NULL;
	for (ote = g_ot_hash[hash]; ote; ote = ote->next) {
		if (ote->fileobj == fileobj) break;
		prev_ote = ote;
	}

	if (!ote) {
		status = STATUS_OBJECT_NAME_NOT_FOUND;
		goto done;
	}

	if (fileobj_type) *fileobj_type = ote->type;

	if (prev_ote) prev_ote->next = ote->next; else g_ot_hash[hash] = ote->next;

	datapipe_free(&ote->in_pipe);
	datapipe_free(&ote->in_oob_pipe);
	
#ifdef DBG
	memset(ote, 0, sizeof(*ote)); // TEST ONLY
#endif

	free(ote);
	status = STATUS_SUCCESS;
done:

	KeReleaseSpinLock(&g_ot_hash_guard, irql);
	return status;
}

ot_entry_t *ot_find_fileobj(PFILE_OBJECT fileobj, KIRQL *irql)
{
	ULONG hash = CALC_HASH(fileobj);
	ot_entry_t *ote;
	NTSTATUS status;

	if (!fileobj) return NULL;

	if (irql) KeAcquireSpinLock(&g_ot_hash_guard, irql);

	for (ote = g_ot_hash[hash]; ote; ote = ote->next)
		if (ote->fileobj == fileobj) break;

	if (!ote) {
		if (irql) KeReleaseSpinLock(&g_ot_hash_guard, *irql);
	}

	return ote;
}

//----------------------------------------------------------------------------

#define CALC_HASH_2(addrobj, conn_ctx)	CALC_HASH((ULONG)(addrobj) ^ (ULONG)(conn_ctx))

NTSTATUS ot_add_conn_ctx(PFILE_OBJECT addrobj, CONNECTION_CONTEXT conn_ctx, PFILE_OBJECT connobj)
{
	ULONG hash = CALC_HASH_2(addrobj, conn_ctx);
	KIRQL irql;
	ctx_entry_t *cte;
	NTSTATUS status;
	int i;

	KeAcquireSpinLock(&g_cte_hash_guard, &irql);
	
	for (cte = g_cte_hash[hash]; cte; cte = cte->next)
		if (cte->addrobj == addrobj && cte->conn_ctx == conn_ctx) break;

	if (!cte) {
		cte = (ctx_entry_t *)malloc_np(sizeof(*cte));
		if (!cte) {
			status = STATUS_NO_MEMORY;
			goto done;
		}
		cte->next = g_cte_hash[hash];
		g_cte_hash[hash] = cte;
	
		cte->addrobj = addrobj;
		cte->conn_ctx = conn_ctx;
	}

	cte->connobj = connobj;
	
	status = STATUS_SUCCESS;
done:

	KeReleaseSpinLock(&g_cte_hash_guard, irql);
	return status;
}

NTSTATUS ot_del_conn_ctx(PFILE_OBJECT addrobj, CONNECTION_CONTEXT conn_ctx)
{
	ULONG hash = CALC_HASH_2(addrobj, conn_ctx);
	KIRQL irql;
	ctx_entry_t *cte, *prev_cte;
	NTSTATUS status;

	KeAcquireSpinLock(&g_cte_hash_guard, &irql);

	prev_cte = NULL;
	for (cte = g_cte_hash[hash]; cte; cte = cte->next) {
		if (cte->addrobj == addrobj && cte->conn_ctx == conn_ctx) break;
		prev_cte = cte;
	}

	if (!cte) {
		status = STATUS_OBJECT_NAME_NOT_FOUND;
		goto done;
	}

	if (prev_cte) prev_cte->next = cte->next; else g_cte_hash[hash] = cte->next;

	free(cte);

	status = STATUS_SUCCESS;
done:

	KeReleaseSpinLock(&g_cte_hash_guard, irql);
	return status;
}

PFILE_OBJECT ot_find_conn_ctx(PFILE_OBJECT addrobj, CONNECTION_CONTEXT conn_ctx)
{
	ULONG hash = CALC_HASH_2(addrobj, conn_ctx);
	KIRQL irql;
	ctx_entry_t *cte;
	NTSTATUS status;
	int i;
	PFILE_OBJECT result = NULL;

	KeAcquireSpinLock(&g_cte_hash_guard, &irql);
	
	for (cte = g_cte_hash[hash]; cte; cte = cte->next)
		if (cte->addrobj == addrobj && cte->conn_ctx == conn_ctx) {
			result = cte->connobj;
			break;
		}

	KeReleaseSpinLock(&g_cte_hash_guard, irql);
	return result;
}

//----------------------------------------------------------------------------
NTSTATUS do_set_old_event_handler(ot_entry_t *ote, int event_type)
{
	NTSTATUS status;
	PIRP query_irp = NULL;
	PDEVICE_OBJECT devobj;

	devobj = ote->devobj;
	if(!devobj)
		return STATUS_UNSUCCESSFUL;

	query_irp = TdiBuildInternalDeviceControlIrp(TDI_SET_EVENT_HANDLER, devobj,
		ote->fileobj, NULL, NULL);
	if (!query_irp) {
		status = STATUS_UNSUCCESSFUL;
		goto done;
	}

	TdiBuildSetEventHandler(query_irp, devobj, ote->fileobj, NULL, NULL, event_type,
		ote->ctx[event_type].old_handler, ote->ctx[event_type].old_context);

	status = IoCallDriver(devobj, query_irp);
	query_irp = NULL;

	if (status) {
		goto done;
	}

	// don't wait to complete

done:
	if (query_irp) IoFreeIrp(query_irp);

	return status;
}
