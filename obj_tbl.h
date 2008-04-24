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

#ifndef _obj_tbl_h_
#define _obj_tbl_h_

#include <tdikrnl.h>
#include "datapipe.h"

NTSTATUS ot_init(void);
void ot_free(void);

#define FILEOBJ_CONTROLOBJ	0
#define FILEOBJ_ADDROBJ		1
#define FILEOBJ_CONNOBJ		2

NTSTATUS ot_add_fileobj(PDEVICE_OBJECT devobj, PFILE_OBJECT fileobj, int fileobj_type, CONNECTION_CONTEXT conn_ctx);
NTSTATUS ot_del_fileobj(PFILE_OBJECT fileobj, int *fileobj_type);

// maximum length of TDI_ADDRESS_TYPE_*
#define TDI_ADDRESS_MAX_LENGTH	TDI_ADDRESS_LENGTH_OSI_TSAP
#define TA_ADDRESS_MAX			(sizeof(TA_ADDRESS) - 1 + TDI_ADDRESS_MAX_LENGTH)
#define TDI_ADDRESS_INFO_MAX	(sizeof(TDI_ADDRESS_INFO) - 1 + TDI_ADDRESS_MAX_LENGTH)

// max event index
#define MAX_EVENT	(TDI_EVENT_ERROR_EX + 1)

/* replaced context */
typedef struct {
	PFILE_OBJECT fileobj;
    PVOID old_handler;
    PVOID old_context;
} TDI_EVENT_CONTEXT;

typedef struct ot_entry {
	ULONG signature;
	struct ot_entry *next;
	PDEVICE_OBJECT devobj;
	PFILE_OBJECT fileobj, associated_fileobj;
	int type;
	TDI_EVENT_CONTEXT ctx[MAX_EVENT];
	UCHAR local_addr[TA_ADDRESS_MAX];
	UCHAR remote_addr[TA_ADDRESS_MAX];
	ULONG out_offset, in_offset, out_oob_offset, in_oob_offset;
	CONNECTION_CONTEXT conn_ctx;
	datapipe_t in_pipe, in_oob_pipe;
	ULONG pid;
	char ProcessName[16];
	UCHAR ipproto; // Protocol for this connection
} ot_entry_t;

ot_entry_t *ot_find_fileobj(PFILE_OBJECT fileobj, KIRQL *irql);
// Note: don't forget KeReleaseSpinLock(&g_ot_hash_guard, irql);

extern KSPIN_LOCK g_ot_hash_guard;

NTSTATUS ot_add_conn_ctx(PFILE_OBJECT addrobj, CONNECTION_CONTEXT conn_ctx, PFILE_OBJECT connobj);
NTSTATUS ot_del_conn_ctx(PFILE_OBJECT addrobj, CONNECTION_CONTEXT conn_ctx);

PFILE_OBJECT ot_find_conn_ctx(PFILE_OBJECT addrobj, CONNECTION_CONTEXT conn_ctx);

#endif
