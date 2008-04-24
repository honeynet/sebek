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
#include "datapipe.h"
#include "memtrack.h"

struct datapipe_entry {
	struct datapipe_entry *next;
	ULONG size;
	char data[];
};

void datapipe_init(datapipe_t *dp)
{
	dp->first = dp->last = NULL;
	KeInitializeSpinLock(&dp->guard);
}

void datapipe_free(datapipe_t *dp)
{
	struct datapipe_entry *de;
	KIRQL irql;
	KeAcquireSpinLock(&dp->guard, &irql);

	for (de = dp->first; de;) {
		struct datapipe_entry *de2 = de->next;
		free(de);
		de = de2;
	}

	KeReleaseSpinLock(&dp->guard, irql);
	memset(dp, 0, sizeof(*dp));
}

ULONG datapipe_peek(datapipe_t *dp)
{
	ULONG result;
	KIRQL irql;
	KeAcquireSpinLock(&dp->guard, &irql);
	
	if (!dp->first) result = 0; else result = dp->first->size;
	
	KeReleaseSpinLock(&dp->guard, irql);
	return result;
}

ULONG datapipe_get(datapipe_t *dp, char *buf, ULONG size)
{
	struct datapipe_entry *de;
	ULONG result = 0;
	KIRQL irql;

	KeAcquireSpinLock(&dp->guard, &irql);
	de = dp->first;

	if (!de) goto done;
	if (de->size > size) goto done;

	dp->first = de->next;

	memcpy(buf, de->data, de->size);
	result = de->size;

	free(de);
done:
	KeReleaseSpinLock(&dp->guard, irql);
	return result;
}

NTSTATUS datapipe_push(datapipe_t *dp, const char *data, ULONG size)
{
	struct datapipe_entry *de;
	KIRQL irql;

	de = (struct datapipe_entry *)malloc_np(sizeof(*de) + size);
	if (!de) return STATUS_NO_MEMORY;

	de->next = NULL;
	de->size = size;
	memcpy(de->data, data, size);

	KeAcquireSpinLock(&dp->guard, &irql);

	if (dp->last) dp->last->next = de; else dp->last = de;
	if (!dp->first) dp->first = dp->last;
	
	KeReleaseSpinLock(&dp->guard, irql);

	return STATUS_SUCCESS;
}
