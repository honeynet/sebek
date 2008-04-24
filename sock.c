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

#include <stdlib.h>
#include <string.h>
#include "sock.h"

u_long
ntohl (u_long netlong)
{
	u_long result = 0;
	((char *)&result)[0] = ((char *)&netlong)[3];
	((char *)&result)[1] = ((char *)&netlong)[2];
	((char *)&result)[2] = ((char *)&netlong)[1];
	((char *)&result)[3] = ((char *)&netlong)[0];
	return result;
}

u_short
ntohs (u_short netshort)
{
	u_short result = 0;
	((char *)&result)[0] = ((char *)&netshort)[1];
	((char *)&result)[1] = ((char *)&netshort)[0];
	return result;
}

u_long
inet_addr(const char *cp)
{
	int a, b, c, d;
	const char *p;
	if(!cp)
		return 0;

	p = cp;

	a = atoi(p);

	p = strchr(p, '.');
	if (p == NULL)
		return INADDR_NONE;
	
	b = atoi(++p);

	p = strchr(p, '.');
	if (p == NULL)
		return INADDR_NONE;

	c = atoi(++p);

	p = strchr(p, '.');
	if (p == NULL)
		return INADDR_NONE;

	d = atoi(++p);

	if (a < 0 || a > 255 ||
		b < 0 || b > 255 ||
		c < 0 || c > 255 ||
		d < 0 || d > 255)
		return 0;

	return (a) | (b << 8) | (c << 16) | (d << 24);
}

u_long
htonl(u_long netlong)
{
	// just reverse byte order
	return ntohl(netlong);
}

u_short
htons(u_short netshort)
{
	// just reverse byte order
	return ntohs(netshort);
}
