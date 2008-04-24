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

/**
 * @file memtrack.h
 * Debug nonpaged pool support.
 * Can help you to find your memory buffers overrun and underrun and memory leaks.
 */

#ifndef _memtrack_h_
#define _memtrack_h_

/** tag for memory blocks */
//lint -e742
#define MEM_TAG		'1VRD'

/**
 * @fn memtrack_init
 * Initialize memory tracking engine
 */

/**
 * @fn memtrack_free
 * Deinitialize memory tracking engine
 */

/**
 * @def malloc_np
 * Allocate memory from nonpaged pool
 * @param	size	size of block
 * @return			address of allocated block in nonpaged pool
 * @retval	NULL	error
 */

/**
 * @def free
 * Free block allocated by malloc_np
 * @param	ptr		pointer to memory block (can't be NULL)
 */

#if DBG

void	memtrack_init(void);

void	memtrack_free(void);

/**
 * Allocate memory from nonpaged pool and store name of file and line of code with this block
 * @param	size	size of block
 * @param	file	name of file to associate with memory block
 * @param	line	line number to associate with memory block
 * @return			address of allocated block in nonpaged pool
 * @retval	NULL	error
 */
void	*mt_malloc(ULONG size, const char *file, ULONG line);

#define malloc_np(size)	mt_malloc((size), __FILE__, __LINE__)	

void free(void *ptr);

#define _TEST_ME_	__asm int 3

#else /* DBG */

#define memtrack_init()
#define memtrack_free()

#define malloc_np(size)	ExAllocatePoolWithTag(NonPagedPool, (size), MEM_TAG)
//lint -e683
#define free(ptr)		ExFreePool(ptr)

/** macro for debug break in checked build */
#define _TEST_ME_

#endif /* DBG */

#endif
