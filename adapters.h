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
 * @file adapters.h
 * Set of functions to work with list of network adapters
 */

#ifndef _adapters_h_
#define _adapters_h_

/**
 * Initialize list of adapters
 */
void	init_adapter_list(void);

/**
 * Deinitialize list of adapters
 */
void	free_adapter_list(void);

/**
 * Add adapter to list
 * @param	name	name of adapter
 * @return			assigned number of adapter
 * @retval	0		error
 */
int		add_adapter(const wchar_t *name);

/**
 * Get list of adapters.
 * Function copies the whole list into wide-char buffer. Names are delimited by (wchar_t)0.
 * Buffer ends by empty unicode string (double (wchar_t)0, (wchar_t)0 at the end of buffer)
 *
 * @param	buf			output buffer for adapter names
 * @param	buf_size	size in wchar_t of buf (can be 0)
 *
 * @return				number of wchar_t has to be in buffer
 *						if greater than buf_size only partial information has been copied
 */
unsigned int		get_adapter_list(wchar_t *buf, unsigned int buf_size);

#endif
