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

#include "logging.h"
#include "sebek.h"
#include "util.h"
#include "exports.h"

//
//  Globals:
//
LOGGING_GLOBALS         g_Logging = {0};
POPEN_INSTANCE					g_pOpenInstance = NULL;
static UINT g_uiSrcIP = 0;

NTSTATUS UninitLogging()
{
	s_LoggingInit = FALSE;

	return STATUS_SUCCESS;
}

NTSTATUS InitLogging()
{
	NDIS_PROTOCOL_CHARACTERISTICS   protocolChar;
	NDIS_STATUS                        status = STATUS_SUCCESS;
	NDIS_STRING                     protoName = NDIS_STRING_CONST("SEBEK");
	NDIS_STRING											DeviceName, DeviceIP, FullDeviceName;
	ANSI_STRING											aDeviceName, aDeviceIP;
	//
	// Initialize the protocol characterstic structure
	//
	
	NdisZeroMemory(&protocolChar, sizeof(NDIS_PROTOCOL_CHARACTERISTICS));

	protocolChar.MajorNdisVersion            = 5;
	protocolChar.MinorNdisVersion            = 0;
	protocolChar.Name                        = protoName;
	protocolChar.OpenAdapterCompleteHandler  = LoggingOpenAdapterComplete;
	protocolChar.CloseAdapterCompleteHandler = LoggingCloseAdapterComplete;
	protocolChar.SendCompleteHandler         = LoggingSendComplete;
	protocolChar.TransferDataCompleteHandler = LoggingTransferDataComplete;
	protocolChar.ResetCompleteHandler        = LoggingResetComplete;
	protocolChar.RequestCompleteHandler      = LoggingRequestComplete;
	protocolChar.ReceiveHandler              = LoggingReceive;
	protocolChar.ReceiveCompleteHandler      = LoggingReceiveComplete;
	protocolChar.StatusHandler               = LoggingStatus;
	protocolChar.StatusCompleteHandler       = LoggingStatusComplete;
	protocolChar.BindAdapterHandler          = LoggingBindAdapter;
	protocolChar.UnbindAdapterHandler        = LoggingUnbindAdapter;
	protocolChar.UnloadHandler               = NULL;
	protocolChar.ReceivePacketHandler        = NULL;
	protocolChar.PnPEventHandler             = LoggingPnPEventHandler;

	//
	// Register as a protocol driver
	//

	NdisRegisterProtocol(
			&status,
			&g_Logging.NdisProtocolHandle,
			&protocolChar,
			sizeof(NDIS_PROTOCOL_CHARACTERISTICS));

	if (status != NDIS_STATUS_SUCCESS) {
			DBGOUT(("Failed to register protocol with NDIS\n"));
			return status;
	}
  
	RtlZeroMemory(&DeviceIP, sizeof(DeviceIP));

	RtlInitAnsiString(&aDeviceName, (PCSZ)g_DeviceName);
	RtlAnsiStringToUnicodeString(&DeviceName, &aDeviceName, TRUE);

	/*
	 *	Find out the device's IP Address
	 *	We currently ONLY support network adapters listed in 
	 *	\HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards
	 *  This means we ONLY support REAL Adapters, not bridged adapters etc.
	 */
	if(GetDeviceInfo(DeviceName.Buffer, &DeviceIP) != STATUS_SUCCESS) {
		RtlFreeUnicodeString(&DeviceName);
		NdisDeregisterProtocol( &status, g_Logging.NdisProtocolHandle);
		return STATUS_UNSUCCESSFUL;
	}

	FullDeviceName.Length=0;
	FullDeviceName.MaximumLength=sizeof(WCHAR) * (DEVICE_SIZE + 16);
	FullDeviceName.Buffer=ExAllocatePool(PagedPool, FullDeviceName.MaximumLength+sizeof(WCHAR));

	if(FullDeviceName.Buffer == NULL) {
		DBGOUT(("Unable to allocate space for DeviceName!\n"));
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Convert our DeviceName into \Device\Name format
	RtlAppendUnicodeToString(&FullDeviceName, L"\\Device\\");
	RtlAppendUnicodeStringToString(&FullDeviceName, &DeviceName);
	RtlFreeUnicodeString(&DeviceName);

	// Convert to ANSI and then to network order
	RtlUnicodeStringToAnsiString(&aDeviceIP, &DeviceIP, TRUE);
	ExFreePool(DeviceIP.Buffer);

	g_uiSrcIP = in_aton(aDeviceIP.Buffer);
	RtlFreeAnsiString(&aDeviceIP);

	LoggingBindAdapter(&status, NULL, &FullDeviceName, NULL, NULL);
	if(status != NDIS_STATUS_SUCCESS) {
		ExFreePool(FullDeviceName.Buffer);
		NdisDeregisterProtocol( &status, g_Logging.NdisProtocolHandle);
		DBGOUT(("Failed to LoggingBindAdapter()\n"));
		return STATUS_UNSUCCESSFUL;
	}

	DBGOUT((" InitLogging: returning %d!\n", status));
	s_LoggingInit = TRUE;
  return status == NDIS_STATUS_SUCCESS ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

VOID
LoggingOpenAdapterComplete(
    IN NDIS_HANDLE                  ProtocolBindingContext,
    IN NDIS_STATUS                  Status,
    IN NDIS_STATUS                  OpenErrorCode
    )
{
    POPEN_INSTANCE           pOpenInstance = NULL;
		
		if(!ProtocolBindingContext)
			return;

    pOpenInstance = (POPEN_INSTANCE)ProtocolBindingContext;
    pOpenInstance->BindStatus = Status;

    NdisSetEvent(&pOpenInstance->BindEvent);
}

VOID
LoggingCloseAdapterComplete(
    IN NDIS_HANDLE                  ProtocolBindingContext,
    IN NDIS_STATUS                  Status
    )
{
    POPEN_INSTANCE           pOpenInstance;

		if(!ProtocolBindingContext)
			return;

    pOpenInstance = (POPEN_INSTANCE)ProtocolBindingContext;
    pOpenInstance->BindStatus = Status;
    NdisSetEvent(&pOpenInstance->BindEvent);
}

VOID
LoggingRefOpen(
    IN POPEN_INSTANCE        pOpenInstance
    )
{
    NdisInterlockedIncrement(&pOpenInstance->RefCount);
}


VOID
LoggingDerefOpen(
    IN POPEN_INSTANCE        pOpenInstance
    )
{
    if (NdisInterlockedDecrement(&pOpenInstance->RefCount) == 0)
    {
        DBGOUT(("DerefOpen: Open %p, Flags %x, ref count is zero!\n",
            pOpenInstance, pOpenInstance->Flags));
        
        LOGGING_ASSERT(pOpenInstance->AdapterHandle == NULL);
        LOGGING_ASSERT(pOpenInstance->RefCount == 0);

				NdisFreeSpinLock(&pOpenInstance->Lock);
				NdisFreeSpinLock(&pOpenInstance->CounterLock);

        //
        //  Free it.
        //
        ExFreePool(pOpenInstance);
    }
}

VOID
LoggingSendComplete(
    IN NDIS_HANDLE                  ProtocolBindingContext,
    IN PNDIS_PACKET                 pNdisPacket,
    IN NDIS_STATUS                  Status
    )
{
    PIRP                        pIrp;
    PIO_STACK_LOCATION          pIrpSp;
    POPEN_INSTANCE       pOpenInstance;
		PNDIS_BUFFER pNdisBuffer;
		PVOID pData;
		UINT DataLength;

		if(!ProtocolBindingContext || !pNdisPacket)
			return;
		
    pOpenInstance = (POPEN_INSTANCE)ProtocolBindingContext;

    pIrp = IRP_FROM_SEND_PKT(pNdisPacket);

		if(pIrp) {
	    //
			//  We are done with the NDIS_PACKET:
			//
			DEREF_SEND_PKT(pNdisPacket);

			//
			//  Complete the Write IRP with the right status.
			//
			pIrpSp = IoGetCurrentIrpStackLocation(pIrp);
			if (Status == NDIS_STATUS_SUCCESS)
			{
					pIrp->IoStatus.Information = pIrpSp->Parameters.Write.Length;
					pIrp->IoStatus.Status = STATUS_SUCCESS;
			}
			else
			{
					pIrp->IoStatus.Information = 0;
					pIrp->IoStatus.Status = STATUS_UNSUCCESSFUL;
			}

			DBGOUT(("SendComplete: packet %p/IRP %p/Length %d "
											"completed with status %x\n",
											pNdisPacket, pIrp, pIrp->IoStatus.Information, pIrp->IoStatus.Status));

			IoCompleteRequest(pIrp, IO_NO_INCREMENT);

			NdisInterlockedDecrement(&pOpenInstance->PendedSendCount);
		} else {
			// We generated the packet.
			NdisUnchainBufferAtFront(pNdisPacket, &pNdisBuffer );
			if(pNdisBuffer)
			{
				NdisQueryBuffer(pNdisBuffer, &pData, &DataLength);
				if(pData)
				{
					NdisFreeMemory(pData, DataLength, 0);
				}
				NdisFreeBuffer(pNdisBuffer);
			}

			//
			//  We are done with the NDIS_PACKET:
			//
			DEREF_SEND_PKT(pNdisPacket);
		}
    DEREF_OPEN(pOpenInstance); // send complete - dequeued send IRP
}

VOID
LoggingTransferDataComplete(
    IN NDIS_HANDLE                  ProtocolBindingContext,
    IN PNDIS_PACKET                 pNdisPacket,
    IN NDIS_STATUS                  TransferStatus,
    IN UINT                         BytesTransferred
    )
{
	return;  
}

VOID
LoggingResetComplete(
    IN NDIS_HANDLE                  ProtocolBindingContext,
    IN NDIS_STATUS                  Status
    )
{
    return;
}

VOID
LoggingRequestComplete(
    IN NDIS_HANDLE                  ProtocolBindingContext,
    IN PNDIS_REQUEST                pNdisRequest,
    IN NDIS_STATUS                  Status
    )
{
    POPEN_INSTANCE       pOpenInstance;
    PREQUEST            pReqContext;

    pOpenInstance = (POPEN_INSTANCE)ProtocolBindingContext;

    //
    //  Get at the request context.
    //
    pReqContext = CONTAINING_RECORD(pNdisRequest, REQUEST, Request);

    //
    //  Save away the completion status.
    //
    pReqContext->Status = Status;

    //
    //  Wake up the thread blocked for this request to complete.
    //
    NdisSetEvent(&pReqContext->ReqEvent);
}

NDIS_STATUS
LoggingReceive(
    IN NDIS_HANDLE                  ProtocolBindingContext,
    IN NDIS_HANDLE                  MacReceiveContext,
    IN PVOID                        pHeaderBuffer,
    IN UINT                         HeaderBufferSize,
    IN PVOID                        pLookaheadBuffer,
    IN UINT                         LookaheadBufferSize,
    IN UINT                         PacketSize
    )
{
    POPEN_INSTANCE   pOpenInstance;
    
    pOpenInstance = (POPEN_INSTANCE)ProtocolBindingContext;
    return NDIS_STATUS_SUCCESS;
}

VOID
LoggingReceiveComplete(
    IN NDIS_HANDLE                  ProtocolBindingContext
    )
{
    POPEN_INSTANCE   pOpenInstance;

    pOpenInstance = (POPEN_INSTANCE)ProtocolBindingContext;

    return;
}

VOID
LoggingStatus(
    IN NDIS_HANDLE                  ProtocolBindingContext,
    IN NDIS_STATUS                  GeneralStatus,
    IN PVOID                        StatusBuffer,
    IN UINT                         StatusBufferSize
    )
{
    POPEN_INSTANCE       pOpenInstance;

    pOpenInstance = (POPEN_INSTANCE)ProtocolBindingContext;

    DBGOUT(("Status: Open %p, Status %x\n",
            pOpenInstance, GeneralStatus));

    NdisAcquireSpinLock(&pOpenInstance->Lock);

    do
    {
        switch(GeneralStatus)
        {
            case NDIS_STATUS_RESET_START:  
                SET_FLAGS(pOpenInstance->Flags,
                               LOGGING_RESET_FLAGS,
                               LOGGING_RESET_IN_PROGRESS);

                break;

            case NDIS_STATUS_RESET_END:  
                SET_FLAGS(pOpenInstance->Flags,
                               LOGGING_RESET_FLAGS,
                               LOGGING_NOT_RESETTING);

                break;

            case NDIS_STATUS_MEDIA_CONNECT:
                SET_FLAGS(pOpenInstance->Flags,
                               LOGGING_MEDIA_FLAGS,
                               LOGGING_MEDIA_CONNECTED);

                break;

            case NDIS_STATUS_MEDIA_DISCONNECT:
                SET_FLAGS(pOpenInstance->Flags,
                               LOGGING_MEDIA_FLAGS,
                               LOGGING_MEDIA_DISCONNECTED);

                break;

            default:
                break;
        }
    }
    while (FALSE);
       
    NdisReleaseSpinLock(&pOpenInstance->Lock);
}

VOID
LoggingStatusComplete(
    IN NDIS_HANDLE                  ProtocolBindingContext
    )
{
    POPEN_INSTANCE       pOpenInstance;

    pOpenInstance = (POPEN_INSTANCE)ProtocolBindingContext;

    return;
}

VOID
LoggingBindAdapter(
    OUT PNDIS_STATUS                pStatus,
    IN NDIS_HANDLE                  BindContext,
    IN PNDIS_STRING                 pDeviceName,
    IN PVOID                        SystemSpecific1,
    IN PVOID                        SystemSpecific2
    )
{
    NDIS_STATUS                     Status, ConfigStatus;
    NDIS_HANDLE                     ConfigHandle;

		if(!pStatus)
			return;

		if(!pDeviceName)
			return;
		
		/* We only want to bind to one adapter, ignore the other calls. */
		if(g_pOpenInstance != NULL || BindContext != NULL) {
			*pStatus = NDIS_STATUS_FAILURE;
			return;
		}

    do
    {
        //
        //  Allocate our context for this open.
        //
				g_pOpenInstance = ExAllocatePool(NonPagedPool, sizeof(OPEN_INSTANCE));
        if (g_pOpenInstance == NULL)
        {
            Status = NDIS_STATUS_RESOURCES;
            break;
        }

        //
        //  Initialize it.
        //
        NdisZeroMemory(g_pOpenInstance, sizeof(OPEN_INSTANCE));

        NdisAllocateSpinLock(&g_pOpenInstance->Lock);
				NdisAllocateSpinLock(&g_pOpenInstance->CounterLock);
        InitializeListHead(&g_pOpenInstance->PendedWrites);
        
        LoggingRefOpen(g_pOpenInstance); // Bind

        //
        //  Set up the NDIS binding.
        //
        Status = LoggingCreateBinding(
                     g_pOpenInstance,
                     (PUCHAR)pDeviceName->Buffer,
                     pDeviceName->Length);
        
        if (Status != NDIS_STATUS_SUCCESS)
        {
            break;
        }
    }
    while (FALSE);

    *pStatus = Status;

    return;
}

VOID
LoggingUnbindAdapter(
    OUT PNDIS_STATUS                pStatus,
    IN NDIS_HANDLE                  ProtocolBindingContext,
    IN NDIS_HANDLE                  UnbindContext
    )
{
    POPEN_INSTANCE           pOpenInstance;

    pOpenInstance = (POPEN_INSTANCE)ProtocolBindingContext;

    //
    //  Mark this open as having seen an Unbind.
    //
    NdisAcquireSpinLock(&pOpenInstance->Lock);

    SET_FLAGS(pOpenInstance->Flags, LOGGING_UNBIND_FLAGS, LOGGING_UNBIND_RECEIVED);

    NdisReleaseSpinLock(&pOpenInstance->Lock);

    LoggingShutdownBinding(pOpenInstance);

    *pStatus = NDIS_STATUS_SUCCESS;
    return;
}

NDIS_STATUS
LoggingCreateBinding(
    IN POPEN_INSTANCE        pOpenInstance,
    IN PUCHAR                       pBindingInfo,
    IN ULONG                        BindingInfoLength
    )
{
    NDIS_STATUS             Status;
    NDIS_STATUS             OpenErrorCode;
    NDIS_MEDIUM             MediumArray[1] = {NdisMedium802_3};
    UINT                    SelectedMediumIndex;
    BOOLEAN                 fDoNotDisturb = FALSE;
    BOOLEAN                 fOpenComplete = FALSE;
    ULONG                   BytesProcessed;

		if(!pOpenInstance)
			return NDIS_STATUS_INVALID_ADDRESS;
		
    DBGOUT(("CreateBinding: open %p/%x, device [%ws]\n",
                pOpenInstance, pOpenInstance->Flags, pBindingInfo));

    Status = NDIS_STATUS_SUCCESS;

    do
    {      
        NdisAcquireSpinLock(&pOpenInstance->Lock);

        //
        //  Check if this open context is already bound/binding/closing.
        //
        if (!TEST_FLAGS(pOpenInstance->Flags, LOGGING_BIND_FLAGS, LOGGING_BIND_IDLE) ||
            TEST_FLAGS(pOpenInstance->Flags, LOGGING_UNBIND_FLAGS, LOGGING_UNBIND_RECEIVED))
        {
            NdisReleaseSpinLock(&pOpenInstance->Lock);

            Status = NDIS_STATUS_NOT_ACCEPTED;

            //
            // Make sure we don't abort this binding on failure cleanup.
            //
            fDoNotDisturb = TRUE;

            break;
        }

        SET_FLAGS(pOpenInstance->Flags, LOGGING_BIND_FLAGS, LOGGING_BIND_OPENING);

        NdisReleaseSpinLock(&pOpenInstance->Lock);

        //
        //  Copy in the device name. Add room for a NULL terminator.
        //
        pOpenInstance->DeviceName.Buffer = ExAllocatePool(NonPagedPool, BindingInfoLength + sizeof(WCHAR));
        if (pOpenInstance->DeviceName.Buffer == NULL)
        {
            DBGOUT(("CreateBinding: failed to alloc device name buf (%d bytes)\n",
                BindingInfoLength + sizeof(WCHAR)));
            Status = NDIS_STATUS_RESOURCES;
            break;
        }

        NdisMoveMemory(pOpenInstance->DeviceName.Buffer, pBindingInfo, BindingInfoLength);
        *(PWCHAR)((PUCHAR)pOpenInstance->DeviceName.Buffer + BindingInfoLength) = L'\0';
        NdisInitUnicodeString(&pOpenInstance->DeviceName, pOpenInstance->DeviceName.Buffer);

        //
        //  Allocate packet pools.
        //
        NdisAllocatePacketPoolEx(
            &Status,
            &pOpenInstance->SendPacketPool,
            MIN_SEND_PACKET_POOL_SIZE,
            MAX_SEND_PACKET_POOL_SIZE - MIN_SEND_PACKET_POOL_SIZE,
            sizeof(SEND_PACKET_RSVD));
       
        if (Status != NDIS_STATUS_SUCCESS)
        {
            DBGOUT(("CreateBinding: failed to alloc"
                    " send packet pool: %x\n", Status));
            break;
        }

				NdisAllocateBufferPool(
            &Status,
            &pOpenInstance->SendBufferPool,
            MAX_SEND_PACKET_POOL_SIZE);
        
        if (Status != NDIS_STATUS_SUCCESS)
        {
            DBGOUT(("CreateBinding: failed to alloc"
                    " send buffer pool: %x\n", Status));
            break;
        }

        NdisSetPacketPoolProtocolId(pOpenInstance->SendPacketPool, NDIS_PROTOCOL_ID_DEFAULT);

        //
        //  Open the adapter.
        //
        NdisInitializeEvent(&pOpenInstance->BindEvent);

        NdisOpenAdapter(
            &Status,
            &OpenErrorCode,
            &pOpenInstance->AdapterHandle,
            &SelectedMediumIndex,
            &MediumArray[0],
            sizeof(MediumArray) / sizeof(NDIS_MEDIUM),
            g_Logging.NdisProtocolHandle,
            (NDIS_HANDLE)pOpenInstance,
            &pOpenInstance->DeviceName,
            0,
            NULL);
    
        if (Status == NDIS_STATUS_PENDING)
        {
            NdisWaitEvent(&pOpenInstance->BindEvent, 0);
            Status = pOpenInstance->BindStatus;
        }

        if (Status != NDIS_STATUS_SUCCESS)
        {
            DBGOUT(("CreateBinding: NdisOpenAdapter (%ws) failed: %x Error Code: %x\n",
                pOpenInstance->DeviceName.Buffer, Status, OpenErrorCode));
            break;
        }

        //
        //  Note down the fact that we have successfully bound.
        //  We don't update the state on the open just yet - this
        //  is to prevent other threads from shutting down the binding.
        //
        fOpenComplete = TRUE;

				//
        // Get Current MAC address
        //
        Status = LoggingDoRequest(
                    pOpenInstance,
                    NdisRequestQueryInformation,
                    OID_802_3_CURRENT_ADDRESS,
                    &pOpenInstance->MAC[0],
                    ETH_ADDR_LEN,
                    &BytesProcessed
                    );
        
        if (Status != NDIS_STATUS_SUCCESS)
        {
            DBGOUT(("CreateBinding: query to get the mac address failed: %x\n",
                    Status));
            break;
        }
				

				//
        //  Get the total frame size.
				//	Note that this INCLUDES the ethernet header.
        //
        Status = LoggingDoRequest(
                    pOpenInstance,
                    NdisRequestQueryInformation,
                    OID_GEN_MAXIMUM_TOTAL_SIZE,
                    &pOpenInstance->TotalFrameSize,
                    sizeof(pOpenInstance->TotalFrameSize),
                    &BytesProcessed
                    );

        if (Status != NDIS_STATUS_SUCCESS)
        {
						DBGOUT(("CreateBinding: query to get the maximum frame size failed: %x\n",
                    Status));
            break;
        }

        //
        //  Mark this open. Also check if we received an Unbind while
        //  we were setting this up.
        //
        NdisAcquireSpinLock(&pOpenInstance->Lock);

        SET_FLAGS(pOpenInstance->Flags, LOGGING_BIND_FLAGS, LOGGING_BIND_ACTIVE);

        //
        //  Did an unbind happen in the meantime?
        //
        if (TEST_FLAGS(pOpenInstance->Flags, LOGGING_UNBIND_FLAGS, LOGGING_UNBIND_RECEIVED))
        {
            Status = NDIS_STATUS_FAILURE;
        }

        NdisReleaseSpinLock(&pOpenInstance->Lock);
        break;

    }
    while (FALSE);

    if ((Status != NDIS_STATUS_SUCCESS) && !fDoNotDisturb)
    {
        NdisAcquireSpinLock(&pOpenInstance->Lock);

        //
        //  Check if we had actually finished opening the adapter.
        //
        if (fOpenComplete)
        {
            SET_FLAGS(pOpenInstance->Flags, LOGGING_BIND_FLAGS, LOGGING_BIND_ACTIVE);
        }
        else if (TEST_FLAGS(pOpenInstance->Flags, LOGGING_BIND_FLAGS, LOGGING_BIND_OPENING))
        {
            SET_FLAGS(pOpenInstance->Flags, LOGGING_BIND_FLAGS, LOGGING_BIND_FAILED);
        }

        NdisReleaseSpinLock(&pOpenInstance->Lock);

        LoggingShutdownBinding(pOpenInstance);
    }

    DBGOUT(("CreateBinding: OpenContext %p, Status %x\n",
            pOpenInstance, Status));

    return (Status);
}

NDIS_STATUS
LoggingDoRequest(
    IN POPEN_INSTANCE        pOpenInstance,
    IN NDIS_REQUEST_TYPE            RequestType,
    IN NDIS_OID                     Oid,
    IN PVOID                        InformationBuffer,
    IN UINT                         InformationBufferLength,
    OUT PUINT                       pBytesProcessed
    )
{
    REQUEST             ReqContext;
    PNDIS_REQUEST               pNdisRequest = &ReqContext.Request;
    NDIS_STATUS                 Status;

		if(!pOpenInstance || !pBytesProcessed)
			return NDIS_STATUS_INVALID_ADDRESS;

    NdisInitializeEvent(&ReqContext.ReqEvent);

    pNdisRequest->RequestType = RequestType;

		//lint -e788
    switch (RequestType)
    {
        case NdisRequestQueryInformation:
            pNdisRequest->DATA.QUERY_INFORMATION.Oid = Oid;
            pNdisRequest->DATA.QUERY_INFORMATION.InformationBuffer =
                                    InformationBuffer;
            pNdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength =
                                    InformationBufferLength;
            break;

        case NdisRequestSetInformation:
            pNdisRequest->DATA.SET_INFORMATION.Oid = Oid;
            pNdisRequest->DATA.SET_INFORMATION.InformationBuffer =
                                    InformationBuffer;
            pNdisRequest->DATA.SET_INFORMATION.InformationBufferLength =
                                    InformationBufferLength;
            break;

        default:
            break;
    }

    NdisRequest(&Status,
                pOpenInstance->AdapterHandle,
                pNdisRequest);
    

    if (Status == NDIS_STATUS_PENDING)
    {
        NdisWaitEvent(&ReqContext.ReqEvent, 0);
        Status = ReqContext.Status;
    }

    if (Status == NDIS_STATUS_SUCCESS)
    {
        *pBytesProcessed = (RequestType == NdisRequestQueryInformation)?
                            pNdisRequest->DATA.QUERY_INFORMATION.BytesWritten:
                            pNdisRequest->DATA.SET_INFORMATION.BytesRead;
        //
        // The driver below should set the correct value to BytesWritten
        // or BytesRead. But now, we just truncate the value to InformationBufferLength if
        // BytesWritten or BytesRead is greater than InformationBufferLength
        //
        if (*pBytesProcessed > InformationBufferLength)
        {
            *pBytesProcessed = InformationBufferLength;
        }
    }

    return (Status);
}

VOID
LoggingShutdownBinding(
    IN POPEN_INSTANCE        pOpenInstance
    )
{
    NDIS_STATUS             Status;
    BOOLEAN                 DoCloseBinding = FALSE;

		if(!pOpenInstance)
			return;

    do
    {
        NdisAcquireSpinLock(&pOpenInstance->Lock);

        if (TEST_FLAGS(pOpenInstance->Flags, LOGGING_BIND_FLAGS, LOGGING_BIND_OPENING))
        {
            //
            //  We are still in the process of setting up this binding.
            //
            NdisReleaseSpinLock(&pOpenInstance->Lock);
            break;
        }

        if (TEST_FLAGS(pOpenInstance->Flags, LOGGING_BIND_FLAGS, LOGGING_BIND_ACTIVE))
        {
            SET_FLAGS(pOpenInstance->Flags, LOGGING_BIND_FLAGS, LOGGING_BIND_CLOSING);
            DoCloseBinding = TRUE;
        }

        NdisReleaseSpinLock(&pOpenInstance->Lock);

        if (DoCloseBinding)
        {
            //
            //  Wait for any pending sends or requests on
            //  the binding to complete.
            //
            LoggingWaitForPendingIO(pOpenInstance, TRUE);

            //
            //  Close the binding now.
            //
            NdisInitializeEvent(&pOpenInstance->BindEvent);

            DBGOUT(("ShutdownBinding: Closing OpenContext %p,"
                    " AdapterHandle %p\n",
                    pOpenInstance, pOpenInstance->AdapterHandle));

            NdisCloseAdapter(&Status, pOpenInstance->AdapterHandle);

            if (Status == NDIS_STATUS_PENDING)
            {
                NdisWaitEvent(&pOpenInstance->BindEvent, 0);
                Status = pOpenInstance->BindStatus;
            }

            pOpenInstance->AdapterHandle = NULL;
        }

        if (DoCloseBinding)
        {
            NdisAcquireSpinLock(&pOpenInstance->Lock);

            SET_FLAGS(pOpenInstance->Flags, LOGGING_BIND_FLAGS, LOGGING_BIND_IDLE);

            SET_FLAGS(pOpenInstance->Flags, LOGGING_UNBIND_FLAGS, 0);

            NdisReleaseSpinLock(&pOpenInstance->Lock);

        }

        //
        //  Remove it from the global list.
        //
        NdisAcquireSpinLock(&g_Logging.GlobalLock);

        NdisReleaseSpinLock(&g_Logging.GlobalLock);

        //
        //  Free any other resources allocated for this bind.
        //
        LoggingFreeBindResources(pOpenInstance);

        LoggingDerefOpen(pOpenInstance);  // Shutdown binding

        break;
    }
    while (FALSE);
}

VOID
LoggingFreeBindResources(
    IN POPEN_INSTANCE       pOpenInstance
    )
{
	if(!pOpenInstance)
		return;

	if(pOpenInstance->SendPacketPool != NULL) {
			NdisFreePacketPool(pOpenInstance->SendPacketPool);
			pOpenInstance->SendPacketPool = NULL;
	}

	if(pOpenInstance->SendBufferPool != NULL) {
			NdisFreeBufferPool(pOpenInstance->SendBufferPool);
			pOpenInstance->SendBufferPool = NULL;
	}

	if(pOpenInstance->DeviceName.Buffer != NULL) {
			ExFreePool(pOpenInstance->DeviceName.Buffer);
			pOpenInstance->DeviceName.Buffer = NULL;
			pOpenInstance->DeviceName.Length =
			pOpenInstance->DeviceName.MaximumLength = 0;
	}
}

VOID
LoggingWaitForPendingIO(
    IN POPEN_INSTANCE            pOpenInstance,
    IN BOOLEAN                          DoCancelReads
    )
{
    NDIS_STATUS     Status;
    ULONG           LoopCount;
    ULONG           PendingCount;

		if(!pOpenInstance)
			return;

    //
    //  Make sure any threads trying to send have finished.
    //
    for (LoopCount = 0; LoopCount < 60; LoopCount++)
    {
        if (pOpenInstance->PendedSendCount == 0)
        {
            break;
        }

        DBGOUT(("WaitForPendingIO: Open %p, %d pended sends\n",
                pOpenInstance, pOpenInstance->PendedSendCount));

        SLEEP(1);
    }
}

NDIS_STATUS
LoggingPnPEventHandler(
    IN NDIS_HANDLE                  ProtocolBindingContext,
    IN PNET_PNP_EVENT               pNetPnPEvent
    )
{
    NDIS_STATUS                     Status;

    switch (pNetPnPEvent->NetEvent)
    {
        case NetEventQueryPower:
        case NetEventBindsComplete:
        case NetEventQueryRemoveDevice:
        case NetEventCancelRemoveDevice:
        case NetEventReconfigure:
        case NetEventBindList:
        case NetEventPnPCapabilities:
            Status = NDIS_STATUS_SUCCESS;
            break;

        default:
            Status = NDIS_STATUS_NOT_SUPPORTED;
            break;
    }

    DBGOUT(("PnPEvent: Open %p, Event %d, Status %x\n",
            ProtocolBindingContext, pNetPnPEvent->NetEvent, Status));

    return (Status);
}

NTSTATUS
LoggingWrite(
    IN CONST PBYTE Data,
    IN UINT DataLength
    )
{
    NTSTATUS                NtStatus;
    NDIS_STATUS             Status;
    POPEN_INSTANCE   pOpenInstance;
    PNDIS_PACKET            pNdisPacket;
    PNDIS_BUFFER            pNdisBuffer;
    PVOID										pDataBuf = NULL;

		if(!Data)
			return STATUS_INVALID_PARAMETER;

    pOpenInstance = g_pOpenInstance;

    pNdisPacket = NULL;

    do
    {
        if (pOpenInstance == NULL)
        {
            DBGOUT(("Write: Not yet associated with a device\n"));
            NtStatus = STATUS_INVALID_HANDLE;
            break;
        }
               
        NdisAcquireSpinLock(&pOpenInstance->Lock);

        if (!TEST_FLAGS(pOpenInstance->Flags, LOGGING_BIND_FLAGS, LOGGING_BIND_ACTIVE))
        {
            NdisReleaseSpinLock(&pOpenInstance->Lock);

            DBGOUT(("Write: Open %p is not bound"
            " or in low power state\n", pOpenInstance));

            NtStatus = STATUS_INVALID_HANDLE;
            break;
        }

        //
        //  Allocate a send packet.
        //
        NdisAllocatePacket(
            &Status,
            &pNdisPacket,
            pOpenInstance->SendPacketPool);
        
        if (Status != NDIS_STATUS_SUCCESS)
        {
            NdisReleaseSpinLock(&pOpenInstance->Lock);

            DBGOUT(("Write: open %p, failed to alloc send pkt\n",
                    pOpenInstance));
            NtStatus = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

				NdisAllocateMemoryWithTag( &pDataBuf, DataLength, SEBEK_TAG);
				memcpy((UCHAR *)pDataBuf, (PVOID)Data, DataLength);

        //
        //  Allocate a send buffer if necessary.
        //
        NdisAllocateBuffer(
            &Status,
            &pNdisBuffer,
            pOpenInstance->SendBufferPool,
            pDataBuf,
            DataLength);

        if (Status != NDIS_STATUS_SUCCESS)
        {
            NdisReleaseSpinLock(&pOpenInstance->Lock);

            NdisFreePacket(pNdisPacket);

            DBGOUT(("Write: open %p, failed to alloc send buf\n",
                    pOpenInstance));
            NtStatus = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        
        NdisInterlockedIncrement(&pOpenInstance->PendedSendCount);

        LoggingRefOpen(pOpenInstance);  // pended send

        //
        //  Initialize the packet ref count. This packet will be freed
        //  when this count goes to zero.
        //
        SEND_PKT_RSVD(pNdisPacket)->RefCount = 1;
        NdisReleaseSpinLock(&pOpenInstance->Lock);

        NtStatus = STATUS_PENDING;

        pNdisBuffer->Next = NULL;
				IRP_FROM_SEND_PKT(pNdisPacket) = NULL; /* so we know we generated this packet */
        NdisChainBufferAtFront(pNdisPacket, pNdisBuffer);
        NdisSendPackets(pOpenInstance->AdapterHandle, &pNdisPacket, 1);

    }
    while (FALSE);

    return (NtStatus);
}

/*
 *	NOTE: We cannot accept data larger then the maximum frame size for the device.
 */
NTSTATUS
WritePacket(
	IN CONST USHORT usType,
	IN CONST ProcessData *pProcessData,
    IN PBYTE Data,
    IN UINT DataLength
    )
{
	UCHAR pPacket[PACKET_BUFFER_SIZE];
	struct ether_hdr *eth;
	struct ip_hdr  *iph;
	struct udp_hdr *udph;
	struct sebek_hdr *sebekh;
	PUCHAR			pPacketData;
	UINT uiPacketLen = SEBEK_PACKET_LEN + DataLength;
	NTSTATUS status;
	CHAR	ProcessName[NT_PROCNAMELEN];
	ANSI_STRING asProcname;
	LARGE_INTEGER CurrentTime, LocalTime = {0, 0};
	KeQuerySystemTime(&CurrentTime);
	ExSystemTimeToLocalTime(&CurrentTime, &LocalTime);

	if(g_pOpenInstance == NULL || Data == NULL)
		return STATUS_UNSUCCESSFUL;

	NdisAcquireSpinLock(&g_pOpenInstance->Lock);
	if(DataLength > g_pOpenInstance->TotalFrameSize) {
		NdisReleaseSpinLock(&g_pOpenInstance->Lock);
		return STATUS_UNSUCCESSFUL;
	}
	NdisReleaseSpinLock(&g_pOpenInstance->Lock);

	RtlZeroMemory(pPacket, sizeof(pPacket));
	pPacketData = pPacket + SEBEK_PACKET_LEN;
	if(Data && DataLength) {
		RtlCopyMemory(pPacketData, Data, DataLength);
}

	eth = (struct ether_hdr *)pPacket;
	
	(void)memcpy(eth->ether_dhost, g_DestMAC, sizeof(eth->ether_dhost));

	NdisAcquireSpinLock(&g_pOpenInstance->Lock);
	(void)memcpy(eth->ether_shost, &g_pOpenInstance->MAC, sizeof(eth->ether_shost));
	NdisReleaseSpinLock(&g_pOpenInstance->Lock);
	
	eth->ether_type = ETHERNET_TYPE_IP;
	
	iph = (struct ip_hdr *)(pPacket + ETH_HEADER_LEN);

	iph->ip_id	= 0;
	iph->ip_hl	= 5;
	iph->ip_v		= 4;
	iph->ip_ttl	= 32;
	iph->ip_tos	= 0;
	iph->ip_p		= IPPROTO_UDP;
	iph->ip_src	= g_uiSrcIP;
	iph->ip_dst	= g_uiDestIP;
	iph->ip_off	= 0;
	iph->ip_len	= htons(IP_HEADER_LEN + UDP_HEADER_LEN + SEBEK_HEADER_LEN + (u_short)DataLength);
	iph->ip_sum	= 0;

	udph = (struct udp_hdr *)(pPacket + ETH_HEADER_LEN + IP_HEADER_LEN);

	udph->uh_sport	= SEBEK_SPORT;
	udph->uh_dport	= g_usDestPort;
	udph->uh_ulen		= htons(UDP_HEADER_LEN + SEBEK_HEADER_LEN + (USHORT)DataLength);
	udph->uh_sum		= 0;

	sebekh = (struct sebek_hdr *)(pPacket + ETH_HEADER_LEN + IP_HEADER_LEN + UDP_HEADER_LEN);
	sebekh->magic = g_uiMagic;
	sebekh->ver   = htons(SEBEK_PROTOCOL_VER);
	sebekh->type	= htons(usType);

	NdisAcquireSpinLock(&g_pOpenInstance->CounterLock);
	NdisInterlockedIncrement(&g_pOpenInstance->PacketCounter);
	sebekh->counter      = htonl(g_pOpenInstance->PacketCounter);
	NdisReleaseSpinLock(&g_pOpenInstance->CounterLock);

	ConvertToSecondsFrom1970(&LocalTime, &sebekh->time_sec, &sebekh->time_usec);
	sebekh->time_sec		 = htonl(sebekh->time_sec);
	sebekh->parent_pid	 = htonl(pProcessData->ulParentPID);
	sebekh->pid          = htonl(pProcessData->ulProcessID);
	sebekh->uid          = 0; // Not implemented
	sebekh->fd           = 0; // Not implemented
	sebekh->inode        = 0; // Not implemented
	
	// XXX: temporary until I figure out how TDI gives me the right IP.
	if(usType == SEBEK_TYPE_SOCKET) {
		struct sbk_sock_rec *pRec = (struct sbk_sock_rec *)(((unsigned char *)sebekh) + sizeof(struct sebek_hdr));
		pRec->sip = g_uiSrcIP;
	}

	// Convert to ANSI
	RtlUnicodeStringToAnsiString(&asProcname, (PUNICODE_STRING)&pProcessData->usProcessName, TRUE);
	memcpy(sebekh->com, asProcname.Buffer, min(SEBEK_HEADER_COMMAND_LEN, asProcname.Length));
	RtlFreeAnsiString(&asProcname);
	
	sebekh->length       = htonl(DataLength);
	iph->ip_sum	= checksum((const USHORT *)iph, iph->ip_hl << 2);

	status = LoggingWrite((PBYTE)pPacket, uiPacketLen); //send raw packet over default interface
	return status;
}

/*
 *	NOTE: We automatically breakup packets based on the maximum amount of data we can send
 *  in one packet.
 */
NTSTATUS
LogData(
		IN CONST USHORT usType,
		IN CONST ProcessData *pProcessData,
    IN PBYTE Data,
    IN ULONG DataLength
    )
{
	ULONG FrameSize = 0, ulNumBlocks = 0, i;
	NTSTATUS status;
	KIRQL irql;

	if(!s_LoggingInit)
		return STATUS_SUCCESS;

	if(!pProcessData)
		return STATUS_INVALID_PARAMETER;
	
	if(g_pOpenInstance == NULL)
		return STATUS_UNSUCCESSFUL;

	NdisAcquireSpinLock(&g_pOpenInstance->Lock);
	FrameSize = g_pOpenInstance->TotalFrameSize;
	NdisReleaseSpinLock(&g_pOpenInstance->Lock);

	// Check for a special case where we don't have any data. This is used to keep the process
	// tree up to date on the server side.
	if(Data == NULL && DataLength == 0) {
		status = WritePacket(usType, pProcessData, NULL, DataLength);
	} else {

		// We add in the extra padding required for the cipher text HERE, because then we
		// Don't need to reassembly packets across packet boundaries in the server.
	FrameSize -= SEBEK_PACKET_LEN;
	ulNumBlocks = (int)(DataLength/FrameSize);
	for(i = 0; i< ulNumBlocks; i++) {
			status = WritePacket(usType, pProcessData, Data + (i * FrameSize), FrameSize);
			if(status != STATUS_SUCCESS) {
			return status;
	}
		}

	// If there is a remaining partial block then send it.
	if((DataLength % FrameSize) > 0) {
			status = WritePacket(usType, pProcessData, Data + (i * FrameSize), DataLength - (i * FrameSize));
			if(status != STATUS_SUCCESS) {
			return status;
	}
		}
}

	return status;
}

NTSTATUS GetDeviceInfo( IN PCWSTR pDeviceName, IN PNDIS_STRING pDeviceIP) {
	NTSTATUS status;
	UNICODE_STRING RegPath;
	ULONG EnableDHCP;
	
	RegPath.Length=0;
  RegPath.MaximumLength=sizeof(WCHAR) * 100;
  RegPath.Buffer=ExAllocatePool(PagedPool, RegPath.MaximumLength+sizeof(WCHAR));

  if(RegPath.Buffer == NULL) 
		return STATUS_INSUFFICIENT_RESOURCES;

	// Get the IP Address
	RtlCopyUnicodeString(&RegPath, 0);
	RtlAppendUnicodeToString(&RegPath, L"Tcpip\\Parameters\\Interfaces\\");
	RtlAppendUnicodeToString(&RegPath, pDeviceName);

	status = RegGetDword(RTL_REGISTRY_SERVICES, RegPath.Buffer, L"EnableDHCP", &EnableDHCP);
	if(status == STATUS_SUCCESS) {
		// Are we DHCP?
		if(EnableDHCP)
			status = RegGetSz(RTL_REGISTRY_SERVICES, RegPath.Buffer, L"DhcpIPAddress", pDeviceIP);
		else
			status = RegGetSz(RTL_REGISTRY_SERVICES, RegPath.Buffer, L"IPAddress", pDeviceIP);
	}

	ExFreePool(RegPath.Buffer);
	DBGOUT(("GetDeviceInfo: returning 0x%x", status));
	return status;
}

USHORT checksum(const USHORT *buffer, unsigned int size) 
{ 
  unsigned long cksum=0;    

	if(!buffer)
		return 0;

  while(size >1) { 
    cksum+=*buffer++; 
    size -=sizeof(USHORT);   
  }      
  if(size) { 
    cksum += *(UCHAR*)buffer;   
  }    
  cksum = (cksum >> 16) + (cksum & 0xffff);   
  cksum += (cksum >>16);   
  return (USHORT)(~cksum); 
} 
