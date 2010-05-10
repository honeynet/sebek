/*
 * Copyright (C) 2001-2010 The Honeynet Project.
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

/* This code is from http://ntdev.h1.ru/ndis_fw.html but was put into public domain by Vlad */

/**
 * @file memtrack.c
 * Implementation of functions for debug nonpaged pool support
 */

#if DBG

#include <ntddk.h>

#include "memtrack.h"
#include "debug.h"

#define MAGIC	'TMEM'
#define INT_3	__asm int 3

struct prefix {
	ULONG		magic;
	struct		prefix *next;
	struct		prefix *prev;
	ULONG		size;
	const char	*file;
	ULONG		line;
	char		data[];
};

struct postfix {
	ULONG	size;
	ULONG	magic;
};

static KSPIN_LOCK guard;
static struct prefix *first, *last;
static ULONG count;

static struct postfix	*check(struct prefix *p);

void
memtrack_init()
{
	KeInitializeSpinLock(&guard);
}

void
memtrack_free()
{
	KIRQL irql;
	ULONG total = 0;

	KeAcquireSpinLock(&guard, &irql);

	if (first != NULL) {
		struct prefix *p;
		for (p = first; p; p = p->next) {
			check(p);

			DBGOUT(("memtrack: memory leak detected! %s:%u (%u bytes)\n",
				p->file, p->line, p->size));

			total += p->size;
		}
	}

	KeReleaseSpinLock(&guard, irql);
	DBGOUT(("memtrack: Total memory leakage: %u bytes (%u blocks)\n", total, count));

	if (total) INT_3;
}

void *
mt_malloc(ULONG size, const char *file, ULONG line)
{
	KIRQL irql;
	struct prefix *data;
	struct postfix *pd;

#if 1
	// check pool integrity
	KeAcquireSpinLock(&guard, &irql);
	
	for (data = first; data; data = data->next)
		check(data);
	
	for (data = last; data; data = data->prev)
		check(data);
	
	KeReleaseSpinLock(&guard, irql);
#endif

	if (size == 0) {
		DBGOUT(("memtrack: mt_malloc: size == 0!\n"));
		INT_3;
		return NULL;
	}

	data = (struct prefix *)ExAllocatePoolWithTag(NonPagedPool,
		sizeof(struct prefix) + size + sizeof(struct postfix),
		'mkbs');
	if (data == NULL)
		return NULL;

	data->magic = MAGIC;
	data->next = NULL;
	data->prev = NULL;
	data->size = size;
	data->file = file;
	data->line = line;

	memset(data->data, 0xcc, size);		// fill by 0xcc: new

	pd = (struct postfix *)(data->data + data->size);

	pd->size = size;
	pd->magic = MAGIC;

	KeAcquireSpinLock(&guard, &irql);
	
	if (last) {
		last->next = data;
		data->prev = last;
		last = data;
	}
	else {
		data->prev = NULL;
		first = last = data;
	}
	count++;

	KeReleaseSpinLock(&guard, irql);
	return data->data;
}

void
free(void *ptr)
{
	KIRQL irql;
	struct prefix *data = (struct prefix *)((char *)ptr - sizeof(struct prefix));
	struct postfix *pd = check(data);

	if (pd == NULL)
		return;

	KeAcquireSpinLock(&guard, &irql);

	if (data->next != NULL)
		data->next->prev = data->prev;
	else
		last = data->prev;
	if (data->prev != NULL)
		data->prev->next = data->next;
	else
		first = data->next;

	memset(data->data, 0xc9, data->size);	// fill by 0xc9: free

	data->size = (ULONG)-1;
	pd->size = (ULONG)-1;

	count--;
	KeReleaseSpinLock(&guard, irql);

	ExFreePool(data);
}

struct postfix *
check(struct prefix *p)
{
	struct postfix *pd;

	if (p->magic != MAGIC) {
		DBGOUT(("memtrack: check: invalid pre-magic! 0x%x\n", p));
		INT_3;
		return NULL;
	}

	pd = (struct postfix *)(p->data + p->size);

	if (pd->magic != MAGIC) {
		DBGOUT(("memtrack: memtrack_free: invalid post-magic! 0x%x\n", pd));
		INT_3;
		return NULL;
	}

	if (p->size != pd->size) {
		DBGOUT(("memtrack: memtracl_free: invalid post-size! 0x%x 0x%x\n", p, pd));
		INT_3;
		return NULL;
	}

	return pd;
}


#endif /* DBG */
