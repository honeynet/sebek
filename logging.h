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

#ifndef LOGGING_H
#define LOGGING_H

#if _MSC_VER > 1000
#pragma once
#endif

#include <ntddk.h>
#include "sebek.h"
#include "sock.h"
#include "net.h"

typedef unsigned char BYTE;
typedef BYTE *				PBYTE;

/*
 *	This defaults to the maximum size of an ethernet frame minus Inter Frame Gap, MAC Preamble, and CRC

 */
#define PACKET_BUFFER_SIZE 1514

typedef struct _LOGGING_GLOBALS
{
	PDRIVER_OBJECT          pDriverObject;
	PDEVICE_OBJECT          ControlDeviceObject;
	NDIS_HANDLE             NdisProtocolHandle;
	NDIS_SPIN_LOCK          GlobalLock;         // to protect the above
	NDIS_STRING    AdapterName;
	PWSTR          BindString;
	PWSTR          ExportString;
} LOGGING_GLOBALS, *PLOGGING_GLOBALS;

typedef struct _OPEN_INSTANCE {
	NDIS_HANDLE				AdapterHandle;
	NDIS_STRING       DeviceName;     // used in NdisOpenAdapter
	NDIS_HANDLE				mPacketPoolH;    
	NDIS_HANDLE				mBufferPoolH;
	NDIS_STATUS				mStatus;
	NDIS_EVENT				BindEvent;
	NDIS_STATUS				BindStatus;
	ULONG             PendedSendCount;
	LIST_ENTRY        PendedReads;    // pended Read IRPs
	ULONG             PendedReadCount;
	NDIS_HANDLE       SendPacketPool;
	NDIS_HANDLE       SendBufferPool;
	LIST_ENTRY        PendedWrites;   // pended Write IRPs
  ULONG             Flags;          // State information
  ULONG             RefCount;
  NDIS_SPIN_LOCK    Lock;
	UCHAR             MAC[ETH_ADDR_LEN];
	ULONG							SrcIP;					// Source IP in network byte order.
	ULONG             TotalFrameSize;
	NDIS_SPIN_LOCK    CounterLock;
	ULONG							PacketCounter; /* Number of packets sent. */
} OPEN_INSTANCE, *POPEN_INSTANCE;

#define SEBEK_TAG 'h1ED'
//
//  Definitions for Flags above.
//
#define LOGGING_BIND_IDLE             0x00000000
#define LOGGING_BIND_OPENING          0x00000001
#define LOGGING_BIND_FAILED           0x00000002
#define LOGGING_BIND_ACTIVE           0x00000004
#define LOGGING_BIND_CLOSING          0x00000008
#define LOGGING_BIND_FLAGS            0x0000000F  // State of the binding

#define LOGGING_OPEN_IDLE             0x00000000
#define LOGGING_OPEN_ACTIVE           0x00000010
#define LOGGING_OPEN_FLAGS            0x000000F0  // State of the I/O open

#define LOGGING_RESET_IN_PROGRESS     0x00000100
#define LOGGING_NOT_RESETTING         0x00000000
#define LOGGING_RESET_FLAGS           0x00000100

#define LOGGING_MEDIA_CONNECTED       0x00000000
#define LOGGING_MEDIA_DISCONNECTED    0x00000200
#define LOGGING_MEDIA_FLAGS           0x00000200

#define LOGGING_READ_SERVICING        0x00100000  // Is the read service
                                                // routine running?
#define LOGGING_READ_FLAGS            0x00100000

#define LOGGING_UNBIND_RECEIVED       0x10000000  // Seen NDIS Unbind?
#define LOGGING_UNBIND_FLAGS          0x10000000

//
//  NDIS Request context structure
//
typedef struct _REQUEST
{
    NDIS_REQUEST            Request;
    NDIS_EVENT              ReqEvent;
    ULONG                   Status;

} REQUEST, *PREQUEST;

//
//  Send packet pool bounds
//
#define MIN_SEND_PACKET_POOL_SIZE    20
#define MAX_SEND_PACKET_POOL_SIZE    400

//
//  ProtocolReserved in sent packets. We save a pointer to the IRP
//  that generated the send.
//
//  The RefCount is used to determine when to free the packet back
//  to its pool. It is used to synchronize between a thread completing
//  a send and a thread attempting to cancel a send.
//
typedef struct _SEND_PACKET_RSVD
{
    PIRP                    pIrp;
    ULONG                   RefCount;

} SEND_PACKET_RSVD, *PSEND_PACKET_RSVD;

#if DBG
#define LOGGING_ASSERT(exp)                                                \
{                                                               \
    if (!(exp))                                                 \
    {                                                           \
        DBGOUT((": assert " #exp " failed in"           \
            " file %s, line %d\n", __FILE__, __LINE__));         \
        DbgBreakPoint();                                        \
    }                                                           \
}
#else
#define LOGGING_ASSERT(exp)
#endif

#define FREE_MEM(_pMem)                \
    NdisFreeMemory(_pMem, 0, 0)

//
//  Send packet context.
//
#define IRP_FROM_SEND_PKT(_pPkt)		\
	(((PSEND_PACKET_RSVD)&((_pPkt)->ProtocolReserved[0]))->pIrp)

#define SEND_PKT_RSVD(_pPkt)           \
    ((PSEND_PACKET_RSVD)&((_pPkt)->ProtocolReserved[0]))


#define REF_SEND_PKT(_pPkt)            \
    (VOID)NdisInterlockedIncrement(&SEND_PKT_RSVD(_pPkt)->RefCount)


#define DEREF_SEND_PKT(_pPkt)          \
    {                                                                               \
        if (NdisInterlockedDecrement(&SEND_PKT_RSVD(_pPkt)->RefCount) == 0)    \
        {                                                                           \
            NdisFreePacket(_pPkt);                                                  \
        }                                                                           \
    }

#define REF_OPEN(_pOpen)   LoggingRefOpen(_pOpen)
#define DEREF_OPEN(_pOpen) LoggingDerefOpen(_pOpen)

#define SET_FLAGS(_FlagsVar, _Mask, _BitsToSet)    \
        ((_FlagsVar) = ((_FlagsVar) & ~(_Mask)) | (_BitsToSet))

#define TEST_FLAGS(_FlagsVar, _Mask, _BitsToCheck)    \
        (((_FlagsVar) & (_Mask)) == (_BitsToCheck))

//
//  Block the calling thread for the given duration:
//
#define SLEEP(_Seconds)                            \
{                                                       \
    NDIS_EVENT  _SleepEvent;                            \
    NdisInitializeEvent(&_SleepEvent);                  \
    (VOID)NdisWaitEvent(&_SleepEvent, _Seconds*1000);   \
}

static BOOLEAN s_LoggingInit = FALSE;

NTSTATUS InitLogging();
NTSTATUS UninitLogging();

VOID
LoggingRefOpen(
    IN POPEN_INSTANCE        pOpenContext
    );

VOID
LoggingDerefOpen(
    IN POPEN_INSTANCE        pOpenContext
    );

VOID
LoggingOpenAdapterComplete(
    IN NDIS_HANDLE                  ProtocolBindingContext,
    IN NDIS_STATUS                  Status,
    IN NDIS_STATUS                  OpenErrorCode
    );

VOID
LoggingCloseAdapterComplete(
    IN NDIS_HANDLE                  ProtocolBindingContext,
    IN NDIS_STATUS                  Status
    );

VOID
LoggingSendComplete(
    IN NDIS_HANDLE                  ProtocolBindingContext,
    IN PNDIS_PACKET                 pNdisPacket,
    IN NDIS_STATUS                  Status
    );

VOID
LoggingTransferDataComplete(
    IN NDIS_HANDLE                  ProtocolBindingContext,
    IN PNDIS_PACKET                 pNdisPacket,
    IN NDIS_STATUS                  TransferStatus,
    IN UINT                         BytesTransferred
    );

VOID
LoggingResetComplete(
    IN NDIS_HANDLE                  ProtocolBindingContext,
    IN NDIS_STATUS                  Status
    );

NDIS_STATUS
LoggingDoRequest(
    IN POPEN_INSTANCE        pOpenInstance,
    IN NDIS_REQUEST_TYPE            RequestType,
    IN NDIS_OID                     Oid,
    IN PVOID                        InformationBuffer,
    IN UINT                         InformationBufferLength,
    OUT PUINT                       pBytesProcessed
    );

VOID
LoggingRequestComplete(
    IN NDIS_HANDLE                  ProtocolBindingContext,
    IN PNDIS_REQUEST                pNdisRequest,
    IN NDIS_STATUS                  Status
    );

NDIS_STATUS
LoggingReceive(
    IN NDIS_HANDLE                  ProtocolBindingContext,
    IN NDIS_HANDLE                  MacReceiveContext,
    IN PVOID                        pHeaderBuffer,
    IN UINT                         HeaderBufferSize,
    IN PVOID                        pLookaheadBuffer,
    IN UINT                         LookaheadBufferSize,
    IN UINT                         PacketSize
    );

VOID
LoggingReceiveComplete(
    IN NDIS_HANDLE                  ProtocolBindingContext
    );

VOID
LoggingStatus(
    IN NDIS_HANDLE                  ProtocolBindingContext,
    IN NDIS_STATUS                  GeneralStatus,
    IN PVOID                        StatusBuffer,
    IN UINT                         StatusBufferSize
    );

VOID
LoggingStatusComplete(
    IN NDIS_HANDLE                  ProtocolBindingContext
    );

VOID
LoggingBindAdapter(
    OUT PNDIS_STATUS                pStatus,
    IN NDIS_HANDLE                  BindContext,
    IN PNDIS_STRING                 pDeviceName,
    IN PVOID                        SystemSpecific1,
    IN PVOID                        SystemSpecific2
    );

VOID
LoggingUnbindAdapter(
    OUT PNDIS_STATUS                pStatus,
    IN NDIS_HANDLE                  ProtocolBindingContext,
    IN NDIS_HANDLE                  UnbindContext
    );

NDIS_STATUS
LoggingCreateBinding(
    IN POPEN_INSTANCE        pOpenInstance,
    IN PUCHAR                       pBindingInfo,
    IN ULONG                        BindingInfoLength
    );

VOID
LoggingShutdownBinding(
    IN POPEN_INSTANCE        pOpenInstance
    );

VOID
LoggingFreeBindResources(
    IN POPEN_INSTANCE       pOpenInstance
    );

VOID
LoggingWaitForPendingIO(
    IN POPEN_INSTANCE            pOpenInstance,
    IN BOOLEAN                          DoCancelReads
    );

NDIS_STATUS
LoggingPnPEventHandler(
    IN NDIS_HANDLE                  ProtocolBindingContext,
    IN PNET_PNP_EVENT               pNetPnPEvent
    );

NTSTATUS
LoggingWrite(
    IN CONST PBYTE Data,
    IN UINT DataLength
    );

// This is the maximum length of data we can support in each of the following UNICODE_STRINGS
#define PROCESSDATA_MAX_LENGTH 64 * sizeof(WCHAR)

typedef struct _ProcessData {
	ULONG ulProcessID;
	ULONG ulParentPID;
	UNICODE_STRING usWindowTitle;
	UNICODE_STRING usProcessName;
	UNICODE_STRING usUsername;
} ProcessData;

extern NPAGED_LOOKASIDE_LIST g_GetProcessLookasideList;
static BOOLEAN FreeProcessData(ProcessData *pProcessData)
{
	if(KeGetCurrentIrql() <= DISPATCH_LEVEL) {
		if(pProcessData->usWindowTitle.Buffer)
			ExFreeToNPagedLookasideList(&g_GetProcessLookasideList, pProcessData->usWindowTitle.Buffer);

		return TRUE;
	} else
		return FALSE;
}

NTSTATUS
LogData(
	IN CONST USHORT usType,
	IN CONST ProcessData *pProcessData,
    IN PBYTE Data,
    IN ULONG DataLength
    );

NTSTATUS
WritePacket(
	IN CONST USHORT usType,
	IN CONST ProcessData *pProcessData,
    IN PBYTE Data,
    IN UINT DataLength
    );

NTSTATUS
GetDeviceInfo(
		IN PCWSTR pDeviceName,
		IN PNDIS_STRING pDeviceIP
		);

USHORT
checksum(
		const USHORT *buffer,
		unsigned int size
		);
#endif
