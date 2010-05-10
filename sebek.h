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

#ifndef SEBEK_H
#define SEBEK_H

#include "debug.h"

#if _WIN32_WINNT >= 0x0500
#define NDIS50 1
#else
#define NDIS40 1
#endif
#include <ndis.h>

/*
 * hooked functions
 */

// typedefs


typedef VOID
NdisRegisterProtocol_t(
	OUT	PNDIS_STATUS			Status,
	OUT	PNDIS_HANDLE			NdisProtocolHandle,
	IN	PNDIS_PROTOCOL_CHARACTERISTICS ProtocolCharacteristics,
	IN	UINT					CharacteristicsLength
	);

typedef VOID
NdisDeregisterProtocol_t(
    OUT PNDIS_STATUS			Status,
    IN NDIS_HANDLE				NdisProtocolHandle
    );

typedef VOID
NdisOpenAdapter_t(
	OUT	PNDIS_STATUS			Status,
	OUT	PNDIS_STATUS			OpenErrorStatus,
	OUT	PNDIS_HANDLE			NdisBindingHandle,
	OUT	PUINT					SelectedMediumIndex,
	IN	PNDIS_MEDIUM			MediumArray,
	IN	UINT					MediumArraySize,
	IN	NDIS_HANDLE				NdisProtocolHandle,
	IN	NDIS_HANDLE				ProtocolBindingContext,
	IN	PNDIS_STRING			AdapterName,
	IN	UINT					OpenOptions,
	IN	PSTRING					AddressingInformation OPTIONAL
	);

typedef VOID
NdisCloseAdapter_t(
	OUT	PNDIS_STATUS			Status,
	IN	NDIS_HANDLE				NdisBindingHandle
	);

// indexes

enum {
	NdisRegisterProtocol_n = 0,
	NdisDeregisterProtocol_n,
	NdisOpenAdapter_n,
	NdisCloseAdapter_n,
	
	MAX_HOOK_FN
};

// array

struct hook_fn {
	char	*name;
	void	*old_fn;
	void	*new_fn;
};

extern struct hook_fn g_hook_fn[MAX_HOOK_FN];

// usage of old functions

#define HOOKED_OLD_FN(name) \
	((name##_t *)(g_hook_fn[name##_n].old_fn))

// new functions

NdisRegisterProtocol_t		new_NdisRegisterProtocol;
NdisDeregisterProtocol_t	new_NdisDeregisterProtocol;
NdisOpenAdapter_t			new_NdisOpenAdapter;
NdisCloseAdapter_t			new_NdisCloseAdapter;


/** struct to store in NDIS packet ProtocolReserved field */
struct protocol_reserved {
	void			*magic;		/**< magic value to indenify this struct */
	PNDIS_BUFFER	buffer;		/**< NDIS buffer with data */
	char			*data;		/**< pointer to data */
};

/** macro to simplify to get struct protocol_reserved from NDIS packet */
#define PROTOCOL_RESERVED(packet)		((struct protocol_reserved *)((packet)->ProtocolReserved))

/**
 * Send packet to network (out).
 * Function can be called at IQL <= DISPATCH_LEVEL.
 * You can safely free packet after calling this function.
 * @param	iface			number of interface (see adapters.h)
 * @param	packet			NDIS packet
 * @retval	STATUS_SUCCESS	no error
 */
NTSTATUS	send_out_packet(int iface, PNDIS_PACKET packet);

/**
 * Send packet to protocol driver (in)
 * Function can be called at IQL <= DISPATCH_LEVEL.
 * You can safely free packet_data after calling this function.
 * @param	iface			number of interface (see adapters.h)
 * @param	hdr_size		size of frame (ethernet) header
 * @param	data_size		size of frame data
 * @param	packet_data		the whole frame to send (size = hdr_size + data_size)
 * @retval	STATUS_SUCCESS	no error
 */
NTSTATUS	send_in_packet(int iface, ULONG hdr_size, ULONG data_size, char *packet_data);

#include <pshpack1.h>

#define SYS_SOCKET      1               /* sys_socket(2)                */
#define SYS_BIND        2               /* sys_bind(2)                  */
#define SYS_CONNECT     3               /* sys_connect(2)               */
#define SYS_LISTEN      4               /* sys_listen(2)                */
#define SYS_ACCEPT      5               /* sys_accept(2)                */

#define SYS_SENDTO      11              /* sys_sendto(2)                */
#define SYS_RECVFROM    12              /* sys_recvfrom(2)              */
#define SYS_SENDMSG     16              /* sys_sendmsg(2)               */
#define SYS_RECVMSG     17              /* sys_recvmsg(2)               */

#define SEBEK_HEADER_COMMAND_LEN 12
#define SEBEK_HEADER_WINDOWTITLE_LEN 32
#define SEBEK_HEADER_USERNAME_LEN 12

#define SEBEK_TYPE_READ 0
#define SEBEK_TYPE_WRITE 1
#define SEBEK_TYPE_SOCKET 2
#define SEBEK_TYPE_OPEN 3

struct sebek_hdr
{
  UINT		magic;
  USHORT  ver;
  USHORT  type;
  UINT		counter;
  UINT		time_sec;
  UINT		time_usec;
  UINT		parent_pid;
  UINT		pid;
  UINT		uid;
  UINT		fd;
  UINT		inode;
  UCHAR		com[SEBEK_HEADER_COMMAND_LEN];
  UINT		length;
};

struct sbk_sock_rec {
	UINT  dip;
	USHORT  dport;
	UINT  sip;
	USHORT  sport;
	USHORT  call;
	UCHAR   proto;
};

#define SEBEK_HEADER_LEN sizeof(struct sebek_hdr)
#define SEBEK_SPORT   19716 // this is in network order. 1101 in host order on x86
#define SEBEK_DPORT   19716	// this is in network order. 1101 in host order on x86
#define SEBEK_MAGIC   208 // this is in network order. 0xD0D0D000 in host order on x86
#define SEBEK_PACKET_LEN (ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN + SEBEK_HEADER_LEN)
#define SEBEK_PROTOCOL_VER 3

#define HELPER_POOL_TAG 'hkbs'

#include <poppack.h>

#endif
