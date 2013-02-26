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

/* This code is from http://ntdev.h1.ru/ndis_fw.html but was put into public domain by Vlad */

/** @addtogroup hook_driver
 *@{
 */

/**
 * @file adapters.c
 * Implementation of functions to work with list of network adapters
 */

#include <ntddk.h>

#include "adapters.h"
#include "memtrack.h"
#include "debug.h"

/** entry of single-linked list of adapters */
struct adapter_entry {
	struct	adapter_entry *next;	/**< next entry */
	wchar_t	name[0];				/**< name of adapter */
};

static struct adapter_entry *g_first;	/**< first entry of list of adapters */
static struct adapter_entry *g_last;	/**< the last entry of list of adapters */
static KSPIN_LOCK g_list_guard;			/**< guard spinlock of list of adapters */
static int g_count;						/**< count of entries in list of adapters */

void
init_adapter_list(void)
{
	KeInitializeSpinLock(&g_list_guard);
	g_first = g_last = NULL;
	g_count = 0;
}

void
free_adapter_list(void)
{
	KIRQL irql;
	struct adapter_entry *adapter;

	KeAcquireSpinLock(&g_list_guard, &irql);

	__try {

		for (adapter = g_first; adapter != NULL;) {
			struct adapter_entry *adapter2 = adapter->next;
			free(adapter);
			adapter = adapter2;
		}

		g_first = g_last = NULL;
		g_count = 0;

	} __finally {
		KeReleaseSpinLock(&g_list_guard, irql);
	}
}

int
add_adapter(const wchar_t *name)
{
	KIRQL irql;
	struct adapter_entry *adapter;
	int result;

	KeAcquireSpinLock(&g_list_guard, &irql);

	__try {
		
		// first try to find adapter by name

		if (g_first != NULL) {
			for (adapter = g_first, result = 1; adapter != NULL; adapter = adapter->next, result++)
				if (wcscmp(adapter->name, name) == 0)
						__leave;
		}

		// not found: add adapter to list

		adapter = (struct adapter_entry *)malloc_np(sizeof(*adapter) +
			(wcslen(name) + 1) * sizeof(wchar_t));
		if (adapter == NULL) {
			DBGOUT(("add_adapter: malloc_np!\n"));
			result = 0;
			__leave;
		}

		adapter->next = NULL;
		wcscpy(adapter->name, name);
	
		if (g_first == NULL)
			g_first = g_last = adapter;
		else {
			g_last->next = adapter;
			g_last = adapter;
		}

		result = ++g_count;

	} __finally {
		KeReleaseSpinLock(&g_list_guard, irql);
	}

	return result;
}

unsigned int
get_adapter_list(wchar_t *buf, unsigned int buf_size)
{
	KIRQL irql;
	struct adapter_entry *adapter;
	unsigned int buf_len, buf_pos;
	if(!buf)
		return 0;

	KeAcquireSpinLock(&g_list_guard, &irql);

	__try {

		buf_pos = 0;
		buf_len = 0;
		for (adapter = g_first; adapter != NULL; adapter = adapter->next) {
			unsigned int len = wcslen(adapter->name);

			if (buf_pos + len + 1 <= buf_size - 1) {
				wcscpy(&buf[buf_pos], adapter->name);
				buf_pos += len + 1;
			}
			
			buf_len += len + 1;
		}
		if (buf_pos < buf_size)
			buf[buf_pos] = L'\0';

	} __finally {
		KeReleaseSpinLock(&g_list_guard, irql);
	}

	return buf_len + 1;
}

/*@}*/
