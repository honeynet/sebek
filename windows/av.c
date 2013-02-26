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

#include <ntddk.h>

#include "av.h"
#include "memtrack.h"
#include "sebek.h"

/** entry contains key-value pair and its type */
struct av_entry {
	struct		av_entry *next;		/**< next entry */
	const void	*key;				/**< key of value to search */
	int			type;				/**< type of pair for search */
	void		*value;				/**< some transparent value */
};

/** number of hash buckets */
#define HASH_SIZE	0x1000
/** get hash by some key */
#define CALC_HASH(key)  (((ULONG)(key) >> 5) % HASH_SIZE)

/** hash for av-pairs */
static struct av_entry **g_av_hash;
/** guard spinlock for hash */
KSPIN_LOCK	g_av_hash_guard;

NTSTATUS
init_av(void)
{
	g_av_hash = (struct av_entry **)malloc_np(sizeof(struct av_entry *) * HASH_SIZE);
	if (g_av_hash == NULL) {
		DBGOUT(("init_av: malloc_np!\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	memset(g_av_hash, 0, sizeof(struct av_entry *) * HASH_SIZE);

	KeInitializeSpinLock(&g_av_hash_guard);

	return STATUS_SUCCESS;
}

void
free_av(void)
{
	ULONG hash;
	struct av_entry *av, *av_next;
	KIRQL irql;

	KeAcquireSpinLock(&g_av_hash_guard, &irql);

	for (hash = 0; hash < HASH_SIZE; hash++) {
		for (av = g_av_hash[hash]; av != NULL;) {
			av_next = av->next;
				
			if (av->value != NULL && av->type > 0)
				free(av->value);
			free(av);

			av = av_next;
		}
	}

	free(g_av_hash);
	g_av_hash = NULL;

	KeReleaseSpinLock(&g_av_hash_guard, irql);
}

NTSTATUS
add_av(const void *key, void *value, int type, BOOLEAN no_guard)
{
	ULONG hash = CALC_HASH(key);
	KIRQL irql;
	struct av_entry *av;
	NTSTATUS status;

	if (!no_guard)
		KeAcquireSpinLock(&g_av_hash_guard, &irql);

	__try {

		for (av = g_av_hash[hash]; av != NULL; av = av->next)
			if (av->key == key && av->type == type)
				break;

		if (av == NULL) {

			av = (struct av_entry *)malloc_np(sizeof(*av));
			if (av == NULL) {
				DBGOUT(("add_av: malloc_np!\n"));
				status = STATUS_INSUFFICIENT_RESOURCES;
				__leave;
			}

			av->next = g_av_hash[hash];
			av->key = key;
			av->value = value;
			av->type = type;

			g_av_hash[hash] = av;

		} else {
			DBGOUT(("add_av: reuse of key 0x%x type %d\n", key, type));

			// change value for av
			if (av->value != NULL && av->type > 0)
				free(av->value);
			av->value = value;
		}

		status = STATUS_SUCCESS;

	} __except((status = (LONG)GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER)) {
		DBGOUT(("add_av: exception 0x%x!\n", status));
	}

	if (!no_guard)
		//lint -e644
		KeReleaseSpinLock(&g_av_hash_guard, irql);

	return status;
}

void *
get_av(const void *key, int type, KIRQL *irql)
{
	ULONG hash = CALC_HASH(key);
	struct av_entry *av;

	if (irql != NULL)
		KeAcquireSpinLock(&g_av_hash_guard, irql);

	for (av = g_av_hash[hash]; av != NULL; av = av->next)
		if (av->key == key && av->type == type)
			return av->value;

	if (irql != NULL)
		KeReleaseSpinLock(&g_av_hash_guard, *irql);
	
	return NULL;
}

NTSTATUS
del_av(const void *key, int type, BOOLEAN no_guard)
{
	ULONG hash = CALC_HASH(key);
	struct av_entry *av, *av_next;
	KIRQL irql;
	NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;

	if (!no_guard)
		KeAcquireSpinLock(&g_av_hash_guard, &irql);

	av_next = NULL;
	for (av = g_av_hash[hash]; av != NULL; av = av->next) {
		if (av->key == key && av->type == type) {
			
			if (av_next != NULL)
				av_next->next = av->next;
			else
				g_av_hash[hash] = av->next;

			if (av->value != NULL && av->type > 0)
				free(av->value);
			free(av);

			status = STATUS_SUCCESS;
			break;
		}

		av_next = av;
	}

	if (!no_guard)
		//lint -e644
		KeReleaseSpinLock(&g_av_hash_guard, irql);
	
	return status;
}
/*@}*/
