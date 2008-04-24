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
#ifdef ENABLE_TDIHOOK
#include <ntddk.h>
#include <tdikrnl.h>
#include "memtrack.h"
#include "obj_tbl.h"
#include "util.h"
#include "tdi_hook.h"
#include "debug.h"
#include "logging.h"
#include "consolespy.h"
#include "packet.h"

#ifndef IoSkipCurrentIrpStackLocation
#	define IoSkipCurrentIrpStackLocation( Irp ) \
	    (Irp)->CurrentLocation++; \
	    (Irp)->Tail.Overlay.CurrentStackLocation++;
#endif

/*--- types ---*/

/* completion info */
typedef struct {
  PIO_COMPLETION_ROUTINE cr;
	PVOID context;
} TDI_COMPLETE_NFO;

/* tdi ioctl dispatcher function */
typedef int tdi_ioctl_fn_t(PIRP, PIO_STACK_LOCATION, TDI_COMPLETE_NFO *);

/*--- prototypes ---*/

static void *tdi_alloc(u_long size);
static char *get_mdl_data(PMDL mdl_data, ULONG *size, int *b_free);
static ULONG write_mdl(PMDL mdl_data, const char *data, ULONG size);

static NTSTATUS HookedDeviceDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp);

static NTSTATUS
tdi_send_irp_to_old_driver(IN PDEVICE_OBJECT dev, IN PIRP irp, TDI_COMPLETE_NFO *tcn);

NTSTATUS
tdi_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);

static NTSTATUS	hook_tcpip(DRIVER_OBJECT *old_DriverObject, DRIVER_OBJECT *new_DriverObject, BOOLEAN b_hook);
static NTSTATUS	get_device_object(wchar_t *name, PDEVICE_OBJECT *devobj);

static __inline BOOL ConvertConnToSocketRecord(IN const ot_entry_t *ote, IN UCHAR call, OUT struct sbk_sock_rec *pRecord) {
	if(!ote || !pRecord)
		return FALSE;
	
	//----- populate buffer
	pRecord->dip   = ((TDI_ADDRESS_IP *)((TA_ADDRESS *)(ote->remote_addr))->Address)->in_addr;
	pRecord->dport = ((TDI_ADDRESS_IP *)((TA_ADDRESS *)(ote->remote_addr))->Address)->sin_port;

	pRecord->sip   = ((TDI_ADDRESS_IP *)((TA_ADDRESS *)(ote->local_addr))->Address)->in_addr;
	pRecord->sport = ((TDI_ADDRESS_IP *)((TA_ADDRESS *)(ote->local_addr))->Address)->sin_port;

	pRecord->proto = ote->ipproto;
	pRecord->call  = htons(call);

	return TRUE;
}

static BOOL LogRecord(const ULONG pid, const struct sbk_sock_rec *pRecord);

NTKERNELAPI
NTSTATUS
ObReferenceObjectByName	(
	IN PUNICODE_STRING	ObjectName,
	IN ULONG			Attributes,
	IN PACCESS_STATE	PassedAccessState OPTIONAL,
	IN ACCESS_MASK		DesiredAccess OPTIONAL,
	IN POBJECT_TYPE		ObjectType OPTIONAL,
	IN KPROCESSOR_MODE	AccessMode,
	IN OUT PVOID		ParseContext OPTIONAL,
	OUT	PVOID			*Object
);

extern POBJECT_TYPE	IoDriverObjectType;

static tdi_ioctl_fn_t
	tdi_associate_address,
	tdi_connect,
	tdi_disassociate_address,
	tdi_receive,
	tdi_receive_datagram,
	tdi_send,
	tdi_send_datagram,
	tdi_set_event_handler;

static tdi_ioctl_fn_t tdi_create, tdi_cleanup;

static NTSTATUS
tdi_event_connect(
    IN PVOID TdiEventContext,
    IN LONG RemoteAddressLength,
    IN PVOID RemoteAddress,
    IN LONG UserDataLength,
    IN PVOID UserData,
    IN LONG OptionsLength,
    IN PVOID Options,
    OUT CONNECTION_CONTEXT *ConnectionContext,
    OUT PIRP *AcceptIrp);

static NTSTATUS
tdi_event_disconnect(
    IN PVOID TdiEventContext,
    IN CONNECTION_CONTEXT ConnectionContext,
    IN LONG DisconnectDataLength,
    IN PVOID DisconnectData,
    IN LONG DisconnectInformationLength,
    IN PVOID DisconnectInformation,
    IN ULONG DisconnectFlags);

static NTSTATUS 
tdi_event_error(
		IN PVOID  TdiEventContext,
		IN NTSTATUS  Status);

static NTSTATUS 
tdi_event_errorex(
		IN PVOID  TdiEventContext,
		IN NTSTATUS  Status,
		IN PVOID Buffer);

static NTSTATUS
tdi_event_receive(
    IN PVOID TdiEventContext,
    IN CONNECTION_CONTEXT ConnectionContext,
    IN ULONG ReceiveFlags,
    IN ULONG BytesIndicated,
    IN ULONG BytesAvailable,
    OUT ULONG *BytesTaken,
    IN PVOID Tsdu,
    OUT PIRP *IoRequestPacket);

static NTSTATUS
tdi_event_receive_datagram(
    IN PVOID TdiEventContext,
    IN LONG SourceAddressLength,
    IN PVOID SourceAddress,
    IN LONG OptionsLength,
    IN PVOID Options,
    IN ULONG ReceiveDatagramFlags,
    IN ULONG BytesIndicated,
    IN ULONG BytesAvailable,
    OUT ULONG *BytesTaken,
    IN PVOID Tsdu,
    OUT PIRP *IoRequestPacket);

static NTSTATUS
tdi_event_receive_expedited(
    IN PVOID TdiEventContext,
    IN CONNECTION_CONTEXT ConnectionContext,
    IN ULONG ReceiveFlags,
    IN ULONG BytesIndicated,
    IN ULONG BytesAvailable,
    OUT ULONG *BytesTaken,
    IN PVOID Tsdu,
    OUT PIRP *IoRequestPacket);

static NTSTATUS
tdi_event_chained_receive(
    IN PVOID TdiEventContext,
    IN CONNECTION_CONTEXT ConnectionContext,
    IN ULONG ReceiveFlags,
    IN ULONG ReceiveLength,
    IN ULONG StartingOffset,
    IN PMDL  Tsdu,
    IN PVOID TsduDescriptor);

static NTSTATUS
tdi_event_chained_receive_datagram(
    IN PVOID TdiEventContext,
    IN LONG SourceAddressLength,
    IN PVOID SourceAddress,
    IN LONG OptionsLength,
    IN PVOID Options,
    IN ULONG ReceiveDatagramFlags,
    IN ULONG ReceiveDatagramLength,
    IN ULONG StartingOffset,
    IN PMDL  Tsdu,
    IN PVOID TsduDescriptor);

static NTSTATUS
tdi_event_chained_receive_expedited(
    IN PVOID TdiEventContext,
    IN CONNECTION_CONTEXT ConnectionContext,
    IN ULONG ReceiveFlags,
    IN ULONG ReceiveLength,
    IN ULONG StartingOffset,
    IN PMDL  Tsdu,
    IN PVOID TsduDescriptor);

/*--- completion routines and their contexts */

typedef struct {
    PIO_COMPLETION_ROUTINE old_cr;
    PVOID old_context;
    PIO_COMPLETION_ROUTINE new_cr;
	PVOID new_context;
	PFILE_OBJECT fileobj;
} TDI_COMPLETION_CTX;

static NTSTATUS
tdi_completion(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);

static NTSTATUS
tdi_create_addrobj_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);

typedef struct {
    MDL *old_mdl;
    char *buf;
} TDI_SEND_CONTEXT;

static NTSTATUS
tdi_send_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);

static NTSTATUS
tdi_receive_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);

static NTSTATUS
tdi_receive_datagram_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);

struct uci_param {
	PFILE_OBJECT	connobj;
	char			address[];
};

static NTSTATUS	update_conn_info_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);
void update_conn_info(PDEVICE_OBJECT devobj, PFILE_OBJECT connobj);

/*--- globals ---*/

// original driver object
DRIVER_OBJECT g_old_DriverObject;
extern PDRIVER_OBJECT g_pTCPIPDriverObject;

/* device objects for: */
PDEVICE_OBJECT
g_tcpfltobj = NULL,		// \Device\Tcp
g_udpfltobj = NULL,		// \Device\Udp
g_rawipfltobj = NULL,		// \Device\RawIp
g_ipfltobj;		// \Device\RawIp

BOOLEAN g_hooked = FALSE;

static struct {
	UCHAR MinorFunction;
	tdi_ioctl_fn_t *fn;
} g_tdi_ioctls[] = {
	{TDI_ASSOCIATE_ADDRESS, tdi_associate_address},
	{TDI_CONNECT, tdi_connect},
	{TDI_DISASSOCIATE_ADDRESS, tdi_disassociate_address},
	{TDI_RECEIVE, tdi_receive},
	{TDI_RECEIVE_DATAGRAM, tdi_receive_datagram},
	{TDI_SEND, tdi_send},
	{TDI_SEND_DATAGRAM, tdi_send_datagram},
	{TDI_SET_EVENT_HANDLER, tdi_set_event_handler}
};

static struct {
	LONG event;
	PVOID handler;
} g_tdi_event_handlers[] = {
	{TDI_EVENT_DISCONNECT, (PVOID)tdi_event_disconnect},
	{TDI_EVENT_ERROR, (PVOID)tdi_event_error},
	{TDI_EVENT_ERROR_EX, (PVOID)tdi_event_errorex},
	{TDI_EVENT_CONNECT, (PVOID)tdi_event_connect},
	{TDI_EVENT_RECEIVE, (PVOID)tdi_event_receive},
	{TDI_EVENT_CHAINED_RECEIVE, (PVOID)tdi_event_chained_receive},
	{TDI_EVENT_RECEIVE_EXPEDITED, (PVOID)tdi_event_receive_expedited},
	{TDI_EVENT_CHAINED_RECEIVE_EXPEDITED, (PVOID)tdi_event_chained_receive_expedited},
	{TDI_EVENT_RECEIVE_DATAGRAM, (PVOID)tdi_event_receive_datagram},
	{TDI_EVENT_CHAINED_RECEIVE_DATAGRAM, (PVOID)tdi_event_chained_receive_datagram}
};

/* initialization */
NTSTATUS InitTDIHook(void)
{
  NTSTATUS status = STATUS_SUCCESS;
  UNICODE_STRING devname;
	int i;

	status = ot_init();
	if (status) {
		DBGOUT(("InitTDIHook: ot_init: 0x%x\n", status));
		goto done;
	}

	/* get device objects for tcp/udp/ip */

	status = get_device_object(L"\\Device\\Tcp", &g_tcpfltobj);
	if (status != STATUS_SUCCESS) {
		DBGOUT(("InitTDIHook: get_device_object(tcp): 0x%x\n", status));
		goto done;
	}
	
	status = get_device_object(L"\\Device\\Udp", &g_udpfltobj);
	if (status != STATUS_SUCCESS) {
		DBGOUT(("InitTDIHook: get_device_object(udp): 0x%x\n", status));
		goto done;
	}
	
	status = get_device_object(L"\\Device\\RawIp", &g_rawipfltobj);
	if (status != STATUS_SUCCESS) {
		DBGOUT(("InitTDIHook: get_device_object(ip): 0x%x\n", status));
		goto done;
	}

	status = get_device_object(L"\\Device\\Ip", &g_ipfltobj);
	if (status != STATUS_SUCCESS) {
		DBGOUT(("InitTDIHook: get_device_object(ip): 0x%x\n", status));
		goto done;
	}

	status = hook_tcpip(&g_old_DriverObject, g_pTCPIPDriverObject, TRUE);
	if (status != STATUS_SUCCESS) {
		DBGOUT(("InitTDIHook: hook_driver: 0x%x\n", status));
		goto done;
	}
	g_hooked = TRUE;

	status = STATUS_SUCCESS;
done:
	if (status != STATUS_SUCCESS) {
		// cleanup
		UnloadTDIHook();
	}

	return status;
}

/* deinitialization */
void UnloadTDIHook(void)
{
	if (g_hooked)
		hook_tcpip(&g_old_DriverObject, g_pTCPIPDriverObject, FALSE);  

	ot_free();
}


/* hook/unhook driver */
NTSTATUS hook_tcpip(DRIVER_OBJECT *old_DriverObject, DRIVER_OBJECT *new_DriverObject, BOOLEAN b_hook)
{
	NTSTATUS status;
	int i;

	if(!old_DriverObject || !new_DriverObject)
		return STATUS_INVALID_PARAMETER;

	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
		if (b_hook) {
			old_DriverObject->MajorFunction[i] = new_DriverObject->MajorFunction[i];
			InterlockedExchange((PLONG)&new_DriverObject->MajorFunction[i], (LONG)HookedDeviceDispatch);
		} else
			new_DriverObject->MajorFunction[i] = old_DriverObject->MajorFunction[i];
	}
	
	return STATUS_SUCCESS;	
}

/* get device object by its name */
NTSTATUS
get_device_object(wchar_t *name, PDEVICE_OBJECT *devobj)
{
	UNICODE_STRING str;
	NTSTATUS status;
	PFILE_OBJECT fileobj;

	RtlInitUnicodeString(&str, name);

	status = IoGetDeviceObjectPointer(&str, FILE_ALL_ACCESS, &fileobj, devobj);
	if (status == STATUS_SUCCESS)
		ObDereferenceObject(fileobj);

	return status;
}

/* dispatch */
NTSTATUS
HookedDeviceDispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp)
{
	PIO_STACK_LOCATION irps;
	NTSTATUS status;
	
	if (!irp) {
		DBGOUT(("HookedDeviceDispatch: !irp\n"));
		return STATUS_SUCCESS;
	}
	
	irps = IoGetCurrentIrpStackLocation(irp);

	if (DeviceObject == g_tcpfltobj ||
		DeviceObject == g_udpfltobj ||
		DeviceObject == g_rawipfltobj ||
		DeviceObject == g_ipfltobj)
	{
		int fa;
		TDI_COMPLETE_NFO tcn;
		NTSTATUS status;
	
		tcn.cr = NULL;
		irp->IoStatus.Status = STATUS_ACCESS_VIOLATION; // default for FILTER_DROP

		switch (irps->MajorFunction) {
			case IRP_MJ_CREATE:
				/* create fileobject */
				fa = tdi_create(irp, irps, &tcn);
				break;

			case IRP_MJ_DEVICE_CONTROL:
				/* try to convert it to IRP_MJ_INTERNAL_DEVICE_CONTROL */
				status = TdiMapUserRequest(DeviceObject, irp, irps);
				if (status)
					break;

				// no break! go to internal device control!
			
			case IRP_MJ_INTERNAL_DEVICE_CONTROL:
			{
				/* ioctl for tdi */
				int i;

				for (i = 0; i < sizeof(g_tdi_ioctls) / sizeof(*g_tdi_ioctls); i++) {
					if (g_tdi_ioctls[i].MinorFunction == irps->MinorFunction) {
						DBGOUT(("HookedDeviceDispatch: IRP_MJ_INTERNAL_DEVICE_CONTROL, minor 0x%x for 0x%08X\n",irps->MinorFunction, irps->FileObject));
						fa = g_tdi_ioctls[i].fn(irp, irps, &tcn);
						break;
					}
				}
		
				//if (i >= sizeof(g_tdi_ioctls) / sizeof(*g_tdi_ioctls))
					//DBGOUT(("HookedDeviceDispatch: IRP_MJ_INTERNAL_DEVICE_CONTROL, minor 0x%x for 0x%08X\n",irps->MinorFunction, irps->FileObject));

				break;
			}

			case IRP_MJ_CLEANUP:
				/* cleanup fileobject */
				fa = tdi_cleanup(irp, irps, &tcn);
				break;

			case IRP_MJ_CLOSE:
				//DBGOUT(("HookedDeviceDispatch: IRP_MJ_CLOSE fileobj 0x%x\n", irps->FileObject));
				break;

			default:
				/*DBGOUT(("HookedDeviceDispatch: major 0x%x, minor 0x%x for 0x%08X\n",	irps->MajorFunction, irps->MinorFunction, irps->FileObject));*/
				break;
		}

		irp->IoStatus.Status = STATUS_SUCCESS;
		return tdi_send_irp_to_old_driver(DeviceObject, irp, &tcn);
	}
	else if(DeviceObject->DriverObject == g_pTCPIPDriverObject) { // XXX: We ignore any unknown Devices that are part of TCPIP
		WCHAR wsz[256];
		UNICODE_STRING oni;
		ULONG len = 255;
		NTSTATUS ntStatus;
		oni.Buffer = wsz;
		oni.Length = 0;
		oni.MaximumLength = sizeof(wsz) - sizeof(WCHAR);
		RtlZeroMemory(wsz, sizeof(wsz)/sizeof(wsz[0]));
		ntStatus = ObQueryNameString(DeviceObject, &oni, oni.MaximumLength, &len);
		if (STATUS_SUCCESS == ntStatus) {
			oni.Buffer[oni.Length / sizeof(WCHAR)] = '\0';
			DBGOUT(("device name = %08X %S\n", DeviceObject, oni.Buffer));
		}
		goto done;
	} else {
		// unknown device object
		DBGOUT(("HookedDeviceDispatch: unknown DeviceObject 0x%x\n", DeviceObject));
		if(KeGetCurrentIrql() == PASSIVE_LEVEL)
			DBGOUT(("HookedDeviceDispatch: unknown Device is %S", DeviceObject->DriverObject->DriverName.Buffer));
	}

	// ALLOW IT!
	/*DBGOUT(("HookedDeviceDispatch: [ALLOW!]  major 0x%x, minor 0x%x for devobj 0x%x; fileobj 0x%x\n",	irps->MajorFunction, irps->MinorFunction, DeviceObject, irps->FileObject));*/

done:
	// call original handler
	status = g_old_DriverObject.MajorFunction[irps->MajorFunction](DeviceObject, irp);

	return status;
}

/* send irp to old driver*/
NTSTATUS
tdi_send_irp_to_old_driver(IN PDEVICE_OBJECT dev, IN PIRP irp, TDI_COMPLETE_NFO *tcn)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(irp);

	if (tcn && tcn->cr) {
		// save old completion routine and context
		TDI_COMPLETION_CTX *ctx = (TDI_COMPLETION_CTX *)malloc_np(sizeof(*ctx));
		if (!ctx) {
			DBGOUT(("tdi_send_irp_to_old_driver: malloc_np\n"));
			irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
			IoCompleteRequest (irp, IO_NO_INCREMENT);
			return irp->IoStatus.Status;
		}

		ctx->old_cr = irps->CompletionRoutine;
		ctx->old_context = irps->Context;
		ctx->new_cr = tcn->cr;
		ctx->new_context = tcn->context;
		ctx->fileobj = irps->FileObject;

		IoSetCompletionRoutine(irp, &tdi_completion, ctx, TRUE, TRUE, TRUE);
	}

	status = g_old_DriverObject.MajorFunction[irps->MajorFunction](dev, irp);
	return status;
}

NTSTATUS
tdi_completion(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	TDI_COMPLETION_CTX *ctx = (TDI_COMPLETION_CTX *)Context;
	NTSTATUS status;
	PIO_STACK_LOCATION irps;

	DBGOUT(("tdi_completion: status 0x%x\n", Irp->IoStatus.Status));

	Irp->CurrentLocation--;
	Irp->Tail.Overlay.CurrentStackLocation--;

	irps = IoGetCurrentIrpStackLocation(Irp);

	DBGOUT(("tdi_completion: DeviceObject = 0x%x; FileObject = 0x%x\n",
		irps->DeviceObject, irps->FileObject));

	if (ctx->new_cr) {
		// restore fileobject
		irps->FileObject = ctx->fileobj;
		
		DBGOUT(("Calling new_cr"));
		status = ctx->new_cr(irps->DeviceObject, Irp, ctx->new_context);
	}

	if (ctx->old_cr) {
		// restore routine and context
		irps->CompletionRoutine = ctx->old_cr;
		irps->Context = ctx->old_context;

		Irp->CurrentLocation++;
		Irp->Tail.Overlay.CurrentStackLocation++;

		DBGOUT(("Calling old_cr"));
		status = ctx->old_cr(irps->DeviceObject, Irp, ctx->old_context);
	}

	free(ctx);
	return status;
}

NTSTATUS
tdi_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	// generic completion
	
	if (Irp->IoStatus.Status)
		DBGOUT(("tdi_complete: status 0x%x\n", Irp->IoStatus.Status));

	if (Irp->PendingReturned) IoMarkIrpPending(Irp);

	return STATUS_SUCCESS;
}

/*[--- TDI dispatchers ---]*/

int
tdi_create(PIRP irp, PIO_STACK_LOCATION irps, TDI_COMPLETE_NFO *tcn)
{
	NTSTATUS status;
	FILE_FULL_EA_INFORMATION *ea = (FILE_FULL_EA_INFORMATION *)irp->AssociatedIrp.SystemBuffer;
				
	if (ea) {
		if (ea->EaNameLength == TDI_TRANSPORT_ADDRESS_LENGTH &&
			memcmp(ea->EaName, TdiTransportAddress, TDI_TRANSPORT_ADDRESS_LENGTH) == 0)
		{
			DBGOUT(("tdi_create: TDI_TRANSPORT"));
			status = ot_add_fileobj(irps->DeviceObject, irps->FileObject, FILEOBJ_ADDROBJ, NULL);
			if (status) {
				DBGOUT(("tdi_create: ot_add_fileobj: 0x%x\n", status));
				return FILTER_IGNORE;
			}

			if(tcn) {
				tcn->cr = tdi_create_addrobj_complete;
				tcn->context = NULL;
			}
		}
		else if (ea->EaNameLength == TDI_CONNECTION_CONTEXT_LENGTH &&
			memcmp(ea->EaName, TdiConnectionContext, TDI_CONNECTION_CONTEXT_LENGTH) == 0)
		{
			CONNECTION_CONTEXT conn_ctx = *(CONNECTION_CONTEXT *)(ea->EaName + ea->EaNameLength + 1);

			DBGOUT(("tdi_create: TDI_CONNECTION_CONTEXT"));
			
			status = ot_add_fileobj(irps->DeviceObject, irps->FileObject, FILEOBJ_CONNOBJ, conn_ctx);
			if (status) {
				DBGOUT(("tdi_create: ot_add_fileobj: 0x%x\n", status));
				return FILTER_IGNORE;
			}
		}
	}

	return FILTER_IGNORE;
}

//----------------------------------------------------------------------------

NTSTATUS
tdi_create_addrobj_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	NTSTATUS status;
	PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(Irp);
	PIRP query_irp = NULL;
	KEVENT event;
	IO_STATUS_BLOCK isb;
	PMDL mdl;
	TDI_ADDRESS_INFO *tai = NULL;
	TA_ADDRESS *addr;
	ot_entry_t *ote = NULL;
	KIRQL irql;

	KdPrint(("[tdi_flt] tdi_create_addrobj_complete: devobj 0x%x; addrobj 0x%x\n",
		DeviceObject, irps->FileObject));

	if (Irp->IoStatus.Status != STATUS_SUCCESS) {
		DBGOUT(("tdi_create_addrobj_complete: status 0x%x\n", Irp->IoStatus.Status));
		goto done;
	} else {
			// query & update connection local_addr
			update_conn_info(DeviceObject, irps->FileObject);
	}

	// query addrobj address:port

	KeInitializeEvent(&event, SynchronizationEvent, FALSE);

	query_irp = TdiBuildInternalDeviceControlIrp(TDI_QUERY_INFORMATION, DeviceObject,	irps->FileObject, &event, &isb);
	if (!query_irp) {
		DBGOUT(("tdi_create_addrobj_complete: TdiBuildInternalDeviceControlIrp\n"));
		status = STATUS_UNSUCCESSFUL;
		goto done;
	}

	tai = (TDI_ADDRESS_INFO *)
		malloc_np(sizeof(TDI_ADDRESS_INFO) + TDI_ADDRESS_MAX_LENGTH);
	if (!tai) {
		DBGOUT(("tdi_create_addrobj_complete: malloc_np\n"));
		status = STATUS_NO_MEMORY;
		goto done;
	}

	mdl = IoAllocateMdl(tai, TDI_ADDRESS_INFO_MAX, FALSE, FALSE, NULL);
	if (!mdl) {
		DBGOUT(("tdi_create_addrobj_complete: IoAllocateMdl\n"));
		status = STATUS_NO_MEMORY;
		goto done;
	}
	MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);

	TdiBuildQueryInformation(query_irp, DeviceObject, irps->FileObject, NULL, NULL,
		TDI_QUERY_ADDRESS_INFO, mdl);

	status = IoCallDriver(DeviceObject, query_irp);
	query_irp = NULL;
	mdl = NULL;

	if (status) {
		DBGOUT(("tdi_create_addrobj_complete: IoCallDriver: 0x%x\n", status));
		goto done;
	}

	status = KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, 0);
	if (status) {
		DBGOUT(("tdi_create_addrobj_complete: KeWaitForSingleObject: 0x%x\n", status));
		goto done;
	}

	addr = tai->Address.Address;

	DBGOUT(("tdi_create_addrobj_complete: address: %x:%u\n", 
		 ntohl(((TDI_ADDRESS_IP *)(addr->Address))->in_addr),
		 ntohs(((TDI_ADDRESS_IP *)(addr->Address))->sin_port)));

	// save address

	ote = ot_find_fileobj(irps->FileObject, &irql);
	if (!ote) {
		DBGOUT(("tdi_create_addrobj_complete: ot_find_fileobj(0x%x)\n",
			irps->FileObject));
		status = STATUS_OBJECT_NAME_NOT_FOUND;
		goto done;
	}

	if (addr->AddressLength > sizeof(ote->local_addr)) {
		DBGOUT(("tdi_create_addrobj_complete: address too long! (%u)\n",
			addr->AddressLength));
		status = STATUS_BUFFER_OVERFLOW;
		goto done;
	}
	memcpy(ote->local_addr, addr, addr->AddressLength);

	DBGOUT(("tdi_create_addrobj_complete: local_addr: %x length:%u\n", 
		((TA_ADDRESS *)ote->local_addr)->Address,
		((TA_ADDRESS *)ote->local_addr)->AddressLength));
	status = STATUS_SUCCESS;
done:
	if (ote) KeReleaseSpinLock(&g_ot_hash_guard, irql);
	if (mdl) IoFreeMdl(mdl);
	if (tai) free(tai);
	if (query_irp) IoFreeIrp(query_irp);

	Irp->IoStatus.Status = status;
	return tdi_complete(DeviceObject, Irp, Context);
}

//----------------------------------------------------------------------------

int
tdi_cleanup(PIRP irp, PIO_STACK_LOCATION irps, TDI_COMPLETE_NFO *tcn)
{
	NTSTATUS status;
	int type;
	CONNECTION_CONTEXT conn_ctx;
	
	status = ot_del_fileobj(irps->FileObject, &type);
	if(status) {
		DBGOUT(("tdi_cleanup: del_fileobj: 0x%x\n", status));
	} else {
		DBGOUT(("tdi_cleanup: fileobj 0x%x, type %d\n", irps->FileObject, type));
	}

	return FILTER_IGNORE;
}

//----------------------------------------------------------------------------

int
tdi_associate_address(PIRP irp, PIO_STACK_LOCATION irps, TDI_COMPLETE_NFO *tcn)
{
	HANDLE addr_handle = ((TDI_REQUEST_KERNEL_ASSOCIATE *)(&irps->Parameters))->AddressHandle;
	PFILE_OBJECT addrobj;
	NTSTATUS status;
	ot_entry_t *ote_conn = NULL;
	KIRQL irql;
	int result = FILTER_IGNORE;

	DBGOUT(("tdi_associate_address: devobj 0x%x; connobj 0x%x\n",
		irps->DeviceObject, irps->FileObject));

	status = ObReferenceObjectByHandle(addr_handle, GENERIC_READ, NULL, KernelMode, &addrobj, NULL);
	if (status) {
		DBGOUT(("tdi_associate_address: ObReferenceObjectByHandle: 0x%x\n", status));
		goto done;
	}

	DBGOUT(("tdi_associate_address: connobj = 0x%x ---> addrobj = 0x%x\n",
		irps->FileObject, addrobj));

	// associate addrobj with connobj

	ote_conn = ot_find_fileobj(irps->FileObject, &irql);
	if (!ote_conn) {
		DBGOUT(("tdi_associate_address: ot_find_fileobj(0x%x)\n", irps->FileObject));
		goto done;
	}
	ote_conn->associated_fileobj = addrobj;

	// add (conn_ctx, addrobj)->connobj

	status = ot_add_conn_ctx(addrobj, ote_conn->conn_ctx, irps->FileObject);
	if (status) {
		DBGOUT(("tdi_associate_address: ot_add_conn_ctx: 0x%x\n", status));
		goto done;
	}

	update_conn_info(irps->DeviceObject, addrobj);

	result = FILTER_IGNORE;
done:
	if (ote_conn) KeReleaseSpinLock(&g_ot_hash_guard, irql);

	return result;
}

//----------------------------------------------------------------------------

int
tdi_connect(PIRP irp, PIO_STACK_LOCATION irps, TDI_COMPLETE_NFO *tcn)
{
	PTDI_REQUEST_KERNEL_CONNECT request = (PTDI_REQUEST_KERNEL_CONNECT)(&irps->Parameters);
	TA_ADDRESS *remote_addr = ((TRANSPORT_ADDRESS *)(request->RequestConnectionInformation->RemoteAddress))->Address;
	PFILE_OBJECT addrobj;
	NTSTATUS status;
	TA_ADDRESS *local_addr;
	int result = FILTER_IGNORE;
	BYTE ipproto;
	ot_entry_t *ote_conn = NULL, *ote_addr;
	KIRQL irql;
	struct sbk_sock_rec log_record;
	ULONG pid;
	BOOL fShouldLog = FALSE;

	DBGOUT(("tdi_connect: IRQL %d connobj 0x%x, address %x:%u\n", KeGetCurrentIrql(),
		irps->FileObject, ntohl(((TDI_ADDRESS_IP *)(remote_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(remote_addr->Address))->sin_port)));

	if (irps->DeviceObject != g_tcpfltobj && irps->DeviceObject != g_udpfltobj) {
		// unknown device object!
		DBGOUT(("tdi_connect: unknown DeviceObject 0x%x\n", irps->DeviceObject));
		goto done;
	}

	ote_conn = ot_find_fileobj(irps->FileObject, &irql);
	if (!ote_conn) {
		DBGOUT(("tdi_connect: ot_find_fileobj(0x%x)\n", irps->FileObject));
		goto done;
	}

	if (irps->DeviceObject == g_tcpfltobj) {
		// get addrobj by connobj and get local address by it

		addrobj = ote_conn->associated_fileobj;
		if (!addrobj) {
			DBGOUT(("tdi_connect: empty addrobj!\n"));
			goto done;
		}

		ote_addr = ot_find_fileobj(addrobj, NULL); // we're already in spinlock
		if (!ote_conn) {
			DBGOUT(("tdi_connect: ot_find_fileobj(0x%x)\n", addrobj));
			goto done;
		}

		update_conn_info(ote_addr->devobj, addrobj);
		ipproto = IPPROTO_TCP;
	}
	else {
		DBGOUT(("tdi_connect: connected UDP socket detected\n"));

		// for connected UDP sockets connobj and addrobj are the same
		addrobj= irps->FileObject;
		ote_addr = ote_conn;

		update_conn_info(ote_addr->devobj, addrobj);
		ipproto = IPPROTO_UDP;
	}

	DBGOUT(("tdi_connect: addrobj 0x%x", addrobj));
	ote_conn->ipproto = ipproto;
	
	local_addr = (TA_ADDRESS *)(ote_addr->local_addr);

	if (local_addr->AddressLength != remote_addr->AddressLength) {
		// what the ...
		DBGOUT(("tdi_connect: different addr lengths! (%u != %u)\n",
			local_addr->AddressLength, remote_addr->AddressLength));
		goto done;
	}

	// associate remote address with connobj
	
	if (remote_addr->AddressLength > sizeof(ote_conn->remote_addr)) {
		DBGOUT(("tdi_connect: address too long! (%u)\n", remote_addr->AddressLength));
		goto done;
	}
	memcpy(ote_conn->remote_addr, remote_addr, remote_addr->AddressLength);

	// associate local address with connobj

	if (local_addr->AddressLength > sizeof(ote_conn->local_addr)) {
		DBGOUT(("tdi_connect: address to long! (%u)\n", local_addr->AddressLength));
		goto done;
	}
	memcpy(ote_conn->local_addr, local_addr, local_addr->AddressLength);

	DBGOUT(("tdi_connect: %s %x:%u -> %x:%u (ipproto = %d)\n", ote_conn->ProcessName,
		ntohl(((TDI_ADDRESS_IP *)(local_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(local_addr->Address))->sin_port),
		ntohl(((TDI_ADDRESS_IP *)(remote_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(remote_addr->Address))->sin_port), ote_conn->ipproto));
	
	if(!ConvertConnToSocketRecord(ote_conn, SYS_CONNECT, &log_record)) {
		DBGOUT(("tdi_connect: Unable to convert connection to socket record!"));
		goto done;
	}

	pid = ote_conn->pid;
	fShouldLog = TRUE;

done:
	if(ote_conn)
		KeReleaseSpinLock(&g_ot_hash_guard, irql);

	if(fShouldLog)
		LogRecord(pid, &log_record);

	return result;
}

//----------------------------------------------------------------------------

int
tdi_disassociate_address(PIRP irp, PIO_STACK_LOCATION irps, TDI_COMPLETE_NFO *tcn)
{
	ot_entry_t *ote_conn = NULL;
	KIRQL irql;
	NTSTATUS status;

	DBGOUT(("tdi_disassociate_address: connobj 0x%x\n", irps->FileObject));

	ote_conn = ot_find_fileobj(irps->FileObject, &irql);
	if (!ote_conn) {
		DBGOUT(("tdi_disassociate_address: ot_find_fileobj(0x%x)\n", irps->FileObject));
		goto done;
	}

	status = ot_del_conn_ctx(ote_conn->associated_fileobj, ote_conn->conn_ctx);
	if (status) {
		DBGOUT(("tdi_disassociate_address: ot_del_conn_ctx: 0x%x\n", status));
		goto done;
	}

done:
	if (ote_conn) KeReleaseSpinLock(&g_ot_hash_guard, irql);

	return FILTER_IGNORE;
}

//----------------------------------------------------------------------------

int
tdi_receive(PIRP irp, PIO_STACK_LOCATION irps, TDI_COMPLETE_NFO *tcn)
{
	TDI_REQUEST_KERNEL_RECEIVE *param = (TDI_REQUEST_KERNEL_RECEIVE *)(&irps->Parameters);
	TA_ADDRESS *local_addr, *remote_addr;
	NTSTATUS status;
	ot_entry_t *ote = NULL;
	KIRQL irql;
	int result = FILTER_IGNORE;
	datapipe_t *pipe;
	ULONG data_size;
	BOOL fShouldLog = FALSE;

	if (irps->DeviceObject != g_tcpfltobj && irps->DeviceObject != g_udpfltobj) {
		// unknown device object!
		DBGOUT(("tdi_receive: unknown DeviceObject 0x%x\n", irps->DeviceObject));
		goto done;
	}

	// get local and remote addresses of connection

	ote = ot_find_fileobj(irps->FileObject, &irql);
	if (!ote) {
		DBGOUT(("tdi_receive: ot_find_fileobj(0x%x)\n", irps->FileObject));
		goto done;
	}

	DBGOUT(("tdi_receive: connobj 0x%x (offset: %u; size: %u)\n", irps->FileObject,
		ote->in_offset, param->ReceiveLength));

	local_addr = (TA_ADDRESS *)(ote->local_addr);
	remote_addr = (TA_ADDRESS *)(ote->remote_addr);

	DBGOUT(("tdi_receive: %s %x:%u -> %x:%u\n", ote->ProcessName,
		ntohl(((TDI_ADDRESS_IP *)(remote_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(remote_addr->Address))->sin_port),
		ntohl(((TDI_ADDRESS_IP *)(local_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(local_addr->Address))->sin_port)));
	
	if (param->ReceiveFlags & TDI_RECEIVE_EXPEDITED)
		ote->in_oob_offset += irp->IoStatus.Information;
	else 
		ote->in_offset += irp->IoStatus.Information;
	

	tcn->cr = tdi_receive_complete;
	tcn->context = irps->FileObject;
	
	fShouldLog = TRUE;
	result = FILTER_IGNORE;
done:
	if (ote) KeReleaseSpinLock(&g_ot_hash_guard, irql);

	return result;
}

//----------------------------------------------------------------------------

NTSTATUS
tdi_receive_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(Irp);
	TDI_REQUEST_KERNEL_RECEIVE *param = (TDI_REQUEST_KERNEL_RECEIVE *)(&irps->Parameters);
	PFILE_OBJECT connobj = (PFILE_OBJECT)Context; // can't use irps->FileObject
	ULONG new_data_size, data_size;
	char *data = NULL, *new_data = NULL;
	PMDL mdl;
	ot_entry_t *ote_conn = NULL;
	KIRQL irql;
	int result = FILTER_IGNORE, b_free_data = 0;
	NTSTATUS status;
	struct sbk_sock_rec log_record;
	ULONG pid;
	BOOL fShouldLog = FALSE;

	DBGOUT(("tdi_receive_complete: connobj 0x%x; status 0x%x\n", connobj,
		Irp->IoStatus.Status));

	if (Irp->IoStatus.Status != STATUS_SUCCESS) {
		DBGOUT(("tdi_receive_complete: status 0x%x\n", Irp->IoStatus.Status));
		goto done;
	}

	ote_conn = ot_find_fileobj(connobj, &irql);
	if (!ote_conn) {
		DBGOUT(("tdi_receive_complete: ot_find_fileobj(0x%x)\n", connobj));
		goto done;
	}

	data = get_mdl_data(Irp->MdlAddress, &data_size, &b_free_data);
	if (!data) {
		DBGOUT(("tdi_receive_complete: get_mdl_data\n"));
		goto done;
	}
	if (Irp->IoStatus.Information > data_size) {
		DBGOUT(("tdi_receive_complete: invalid data size %u > %u\n",
			Irp->IoStatus.Information, data_size));
		goto done;
	}

	if(!ConvertConnToSocketRecord(ote_conn, SYS_RECVMSG, &log_record)) {
		DBGOUT(("tdi_receive_complete: Unable to convert connection to socket record!"));
		goto done;
	}

	pid = ote_conn->pid;
	fShouldLog = TRUE;
done:
		if (param->ReceiveFlags & TDI_RECEIVE_EXPEDITED)
			ote_conn->in_oob_offset += Irp->IoStatus.Information;
		else ote_conn->in_offset += Irp->IoStatus.Information;

	if(fShouldLog)
		LogRecord(pid, &log_record);

	if (ote_conn) KeReleaseSpinLock(&g_ot_hash_guard, irql);
	if (b_free_data && data) free(data);
	if (new_data) free(new_data);

	return tdi_complete(DeviceObject, Irp, Context);
}

//----------------------------------------------------------------------------

int
tdi_receive_datagram(PIRP irp, PIO_STACK_LOCATION irps, TDI_COMPLETE_NFO *tcn)
{
	TDI_REQUEST_KERNEL_RECEIVEDG *param = (TDI_REQUEST_KERNEL_RECEIVEDG *)(&irps->Parameters);
	ot_entry_t *ote_addr = NULL;
	KIRQL irql;
	TA_ADDRESS *local_addr, *remote_addr;
	int result = FILTER_IGNORE, ipproto;
	ULONG data_size;

	if (irps->DeviceObject != g_udpfltobj && irps->DeviceObject != g_rawipfltobj && irps->DeviceObject != g_ipfltobj) {
		// unknown device object!
		DBGOUT(("tdi_receive_datagram: unknown DeviceObject 0x%x\n", irps->DeviceObject));
		goto done;
	}
	if (irps->DeviceObject == g_udpfltobj) ipproto = IPPROTO_UDP; else ipproto = IPPROTO_IP;

	// get local address

	ote_addr = ot_find_fileobj(irps->FileObject, &irql);
	if (!ote_addr) {
		DBGOUT(("tdi_receive_datagram: ot_find_fileobj(0x%x)\n", irps->FileObject));
		goto done;
	}

	DBGOUT(("tdi_receive_datagram: devobj 0x%x; addrobj 0x%x (offset: %u; size: %u)\n",
		irps->DeviceObject, irps->FileObject, ote_addr->in_offset, param->ReceiveLength));

	local_addr = (TA_ADDRESS *)(ote_addr->local_addr);
	remote_addr = ((TRANSPORT_ADDRESS *)(param->ReceiveDatagramInformation->RemoteAddress))->Address;

	DBGOUT(("tdi_receive_datagram: %s %x:%u -> %x:%u (ipproto = %d)\n", ote_addr->ProcessName,
		ntohl(((TDI_ADDRESS_IP *)(remote_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(remote_addr->Address))->sin_port),
		ntohl(((TDI_ADDRESS_IP *)(local_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(local_addr->Address))->sin_port), ipproto));

	
	ote_addr->in_offset += irp->IoStatus.Information;

	tcn->cr = tdi_receive_datagram_complete;
	tcn->context = NULL;

done:
	if (ote_addr) KeReleaseSpinLock(&g_ot_hash_guard, irql);

	return result;
}

//----------------------------------------------------------------------------

NTSTATUS
tdi_receive_datagram_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(Irp);
	TDI_REQUEST_KERNEL_RECEIVE *param = (TDI_REQUEST_KERNEL_RECEIVE *)(&irps->Parameters);
	ULONG new_data_size, data_size;
	char *data = NULL, *new_data = NULL;
	PMDL mdl;
	ot_entry_t *ote = NULL;
	KIRQL irql;
	int b_free_data = 0;
	NTSTATUS status;
	struct sbk_sock_rec log_record;
	ULONG pid;
	BOOL fShouldLog = FALSE;

	DBGOUT(("tdi_receive_datagram_complete: connobj 0x%x; status 0x%x\n", irps->FileObject,
		Irp->IoStatus.Status));

	if (Irp->IoStatus.Status != STATUS_SUCCESS) {
		DBGOUT(("tdi_receive_datagram_complete: status 0x%x\n", Irp->IoStatus.Status));
		goto done;
	}

	ote = ot_find_fileobj(irps->FileObject, &irql);
	if (!ote) {
		DBGOUT(("tdi_receive_datagram_complete: ot_find_fileobj(0x%x)\n", irps->FileObject));
		goto done;
	}

	data = get_mdl_data(Irp->MdlAddress, &data_size, &b_free_data);
	if (!data) {
		DBGOUT(("tdi_receive_datagram_complete: get_mdl_data\n"));
		goto done;
	}
	if (Irp->IoStatus.Information > data_size) {
		DBGOUT(("tdi_receive_datagram_complete: invalid data size %u > %u\n",
			Irp->IoStatus.Information, data_size));
		goto done;
	}

	if(!ConvertConnToSocketRecord(ote, SYS_RECVFROM, &log_record)) {
		DBGOUT(("tdi_receive_datagram_complete: Unable to convert connection to socket record!"));
		goto done;
	}

	pid = ote->pid;
	fShouldLog = TRUE;

done:
	ote->in_offset += Irp->IoStatus.Information;

	if(fShouldLog)
		LogRecord(pid, &log_record);

	if (ote) KeReleaseSpinLock(&g_ot_hash_guard, irql);
	if (b_free_data && data) free(data);
	if (new_data) free(new_data);

	return tdi_complete(DeviceObject, Irp, Context);
}

//----------------------------------------------------------------------------

int
tdi_send(PIRP irp, PIO_STACK_LOCATION irps, TDI_COMPLETE_NFO *tcn)
{
	TDI_REQUEST_KERNEL_SEND *param = (TDI_REQUEST_KERNEL_SEND *)(&irps->Parameters);
	TA_ADDRESS *local_addr, *remote_addr;
	NTSTATUS status;
	ULONG new_data_size, data_size;
	char *data = NULL, *new_data = NULL;
	PMDL mdl;
	TDI_SEND_CONTEXT *ctx = NULL;
	ot_entry_t *ote_conn = NULL;
	KIRQL irql;
	int b_free_data = 0;

	if (irps->DeviceObject != g_tcpfltobj && irps->DeviceObject != g_udpfltobj) {
		// unknown device object!
		DBGOUT(("tdi_send: unknown DeviceObject 0x%x\n", irps->DeviceObject));
		goto done;
	}

	// get local and remote addresses of connection

	ote_conn = ot_find_fileobj(irps->FileObject, &irql);
	if (!ote_conn) {
		DBGOUT(("tdi_send: ot_find_fileobj(0x%x)\n", irps->FileObject));
		goto done;
	}

	DBGOUT(("tdi_send: connobj 0x%x (offset: %u; size: %u)\n", irps->FileObject,
		ote_conn->out_offset, param->SendLength));

	local_addr = (TA_ADDRESS *)(ote_conn->local_addr);
	remote_addr = (TA_ADDRESS *)(ote_conn->remote_addr);

	DBGOUT(("tdi_send: %s %x:%u -> %x:%u\n", ote_conn->ProcessName,
		ntohl(((TDI_ADDRESS_IP *)(local_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(local_addr->Address))->sin_port),
		ntohl(((TDI_ADDRESS_IP *)(remote_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(remote_addr->Address))->sin_port)));

done:
	if (ote_conn) {
		if (param->SendFlags & TDI_SEND_EXPEDITED) ote_conn->out_oob_offset += param->SendLength;
		else ote_conn->out_offset += param->SendLength;
		
		KeReleaseSpinLock(&g_ot_hash_guard, irql);
	}
	if (b_free_data && data) free(data);
	if (ctx) free(ctx);
	if (new_data) free(new_data);

	return FILTER_IGNORE;
}

//----------------------------------------------------------------------------

// this function destroys replaced MDL at completion
// used not for only TDI_SEND
NTSTATUS
tdi_send_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(Irp);
	ot_entry_t *ote = NULL;
	KIRQL irql;
	struct sbk_sock_rec log_record;
	ULONG pid;
	TDI_SEND_CONTEXT *ctx = (TDI_SEND_CONTEXT *)Context;
	BOOL fShouldLog = FALSE;

	DBGOUT(("tdi_send_complete: connobj 0x%x; status 0x%x\n", irps->FileObject,
		Irp->IoStatus.Status));

	if (Irp->IoStatus.Status != STATUS_SUCCESS) {
		DBGOUT(("tdi_send_complete: status 0x%x\n", Irp->IoStatus.Status));
		goto done;
	}

	ote = ot_find_fileobj(irps->FileObject, &irql);
	if (!ote) {
		DBGOUT(("tdi_send_complete: ot_find_fileobj(0x%x)\n", irps->FileObject));
		goto done;
	}

	if(!ConvertConnToSocketRecord(ote, SYS_SENDMSG, &log_record)) {
		DBGOUT(("tdi_send_complete: Unable to convert connection to socket record!"));
		goto done;
	}

	pid = ote->pid;
	fShouldLog = TRUE;
   
done:
	// destroy replaced MDL
	IoFreeMdl(Irp->MdlAddress);

	// replace MDL back
	Irp->MdlAddress = ctx->old_mdl;

	// free memory
	free(ctx->buf);
	free(ctx);

	if(fShouldLog)
		LogRecord(pid, &log_record);

	if (ote) KeReleaseSpinLock(&g_ot_hash_guard, irql);

	return tdi_complete(DeviceObject, Irp, Context);
}

//----------------------------------------------------------------------------

int
tdi_send_datagram(PIRP irp, PIO_STACK_LOCATION irps, TDI_COMPLETE_NFO *tcn)
{
	TDI_REQUEST_KERNEL_SENDDG *param = (TDI_REQUEST_KERNEL_SENDDG *)(&irps->Parameters);
	ot_entry_t *ote = NULL;
	KIRQL irql;
	TA_ADDRESS *local_addr, *remote_addr;
	int result = FILTER_IGNORE, b_free_data = 0, ipproto;
	char *new_data = NULL, *data = NULL, local_buf[TA_ADDRESS_MAX];
	TDI_SEND_CONTEXT *ctx = NULL;
	ULONG data_size, new_data_size;
	PMDL mdl;
	struct sbk_sock_rec log_record;
	ULONG pid;
	BOOL fShouldLog = FALSE;

	if (irps->DeviceObject != g_udpfltobj && irps->DeviceObject != g_rawipfltobj && irps->DeviceObject != g_ipfltobj) {
		// unknown device object!
		DBGOUT(("tdi_send_datagram: unknown DeviceObject 0x%x\n", irps->DeviceObject));
		goto done;
	}
	if(irps->DeviceObject == g_udpfltobj) 
		ipproto = IPPROTO_UDP; 
	else 
		ipproto = IPPROTO_IP;

	// get local address

	ote = ot_find_fileobj(irps->FileObject, &irql);
	if (!ote) {
		DBGOUT(("tdi_send_datagram: ot_find_fileobj(0x%x)\n", irps->FileObject));
		goto done;
	}

	local_addr = (TA_ADDRESS *)(ote->local_addr);
	remote_addr = ((TRANSPORT_ADDRESS *)(param->SendDatagramInformation->RemoteAddress))->Address;

	DBGOUT(("tdi_send_datagram: %s %x:%u -> %x:%u (ipproto = %d)\n", ote->ProcessName,
		ntohl(((TDI_ADDRESS_IP *)(local_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(local_addr->Address))->sin_port),
		ntohl(((TDI_ADDRESS_IP *)(remote_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(remote_addr->Address))->sin_port), ipproto));

	if(!ConvertConnToSocketRecord(ote, SYS_SENDTO, &log_record)) {
		DBGOUT(("tdi_send_complete: Unable to convert connection to socket record!"));
		goto done;
	}

	pid = ote->pid;
	fShouldLog = TRUE;

	ote->out_offset += param->SendLength;

done:
	if (ote) KeReleaseSpinLock(&g_ot_hash_guard, irql);
	if (b_free_data && data) free(data);
	if (ctx) free(ctx);
	if (new_data) free(new_data);

	if(fShouldLog)
		LogRecord(pid, &log_record);

	return result;
}

//----------------------------------------------------------------------------

int
tdi_set_event_handler(PIRP irp, PIO_STACK_LOCATION irps, TDI_COMPLETE_NFO *tcn)
{
	PTDI_REQUEST_KERNEL_SET_EVENT r = (PTDI_REQUEST_KERNEL_SET_EVENT)&irps->Parameters;
	NTSTATUS status;
	ot_entry_t *ote = NULL;
	KIRQL irql;
	int result = FILTER_IGNORE;
	TDI_EVENT_CONTEXT *ctx;

	ote = ot_find_fileobj(irps->FileObject, &irql);
	if (!ote) {
		DBGOUT(("tdi_set_event_handler: ot_find_fileobj(0x%x)\n", irps->FileObject));
		if (!r->EventHandler) result = FILTER_IGNORE; // earlier than our load fileobjects
		goto done;
	}

	DBGOUT(("tdi_set_event_handler: EventType: %d", r->EventType));

	if (r->EventType < 0 || r->EventType >= MAX_EVENT) {
		DBGOUT(("tdi_set_event_handler: unknown EventType %d! MAX_EVENT: %d\n", r->EventType, MAX_EVENT));
		result = FILTER_IGNORE;
		goto done;
	}

	ctx = &ote->ctx[r->EventType];

	if (r->EventHandler) {
		/* add EventHandler */
		int i;

		for (i = 0; i < sizeof(g_tdi_event_handlers) / sizeof(*g_tdi_event_handlers); i++)
			if (g_tdi_event_handlers[i].event == r->EventType) break;

		if (i >= sizeof(g_tdi_event_handlers) / sizeof(*g_tdi_event_handlers)) {
			DBGOUT(("tdi_set_event_handler: unknown EventType %d!\n", r->EventType));
			result = FILTER_IGNORE;
			goto done;
		}

		ctx->old_handler = r->EventHandler;
		ctx->old_context = r->EventContext;

		r->EventHandler = g_tdi_event_handlers[i].handler;
		r->EventContext = ctx;
	}
	else {
		/* remove EventHandler */
		ctx->old_handler = NULL;
		ctx->old_context = NULL;
	}

	result = FILTER_IGNORE;
done:
	if (ote) KeReleaseSpinLock(&g_ot_hash_guard, irql);

	return result;
}

/*[--- TDI event handlers ---]*/

NTSTATUS
tdi_event_connect(
    IN PVOID TdiEventContext,
    IN LONG RemoteAddressLength,
    IN PVOID RemoteAddress,
    IN LONG UserDataLength,
    IN PVOID UserData,
    IN LONG OptionsLength,
    IN PVOID Options,
    OUT CONNECTION_CONTEXT *ConnectionContext,
    OUT PIRP *AcceptIrp)
{
	TDI_EVENT_CONTEXT *ctx = (TDI_EVENT_CONTEXT *)TdiEventContext;
	TA_ADDRESS *remote_addr = ((TRANSPORT_ADDRESS *)RemoteAddress)->Address, *local_addr;
	ot_entry_t *ote_addr = NULL, *ote_conn = NULL;
	KIRQL irql;
	NTSTATUS status;
	PIO_STACK_LOCATION irps = NULL;
	struct sbk_sock_rec log_record;
	BOOL fShouldLog = FALSE;
	ULONG pid;

	ote_addr = ot_find_fileobj(ctx->fileobj, &irql);
	if (!ote_addr) {
		DBGOUT(("tdi_event_connect: ot_find_fileobj(0x%x)\n", ctx->fileobj));
		goto done;
	}

	local_addr = (TA_ADDRESS *)(ote_addr->local_addr);

	DBGOUT(("tdi_event_connect: %s %x:%u -> %x:%u\n", ote_addr->ProcessName,
		ntohl(((TDI_ADDRESS_IP *)(remote_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(remote_addr->Address))->sin_port),
		ntohl(((TDI_ADDRESS_IP *)(local_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(local_addr->Address))->sin_port)));

	// run handler
	status = ((PTDI_IND_CONNECT)(ctx->old_handler))
		(ctx->old_context, RemoteAddressLength, RemoteAddress,
		UserDataLength, UserData, OptionsLength, Options, ConnectionContext,
		AcceptIrp);

	if (!*AcceptIrp) goto done;

	// create and initialize connobj

	irps = IoGetCurrentIrpStackLocation(*AcceptIrp);
	
	KeReleaseSpinLock(&g_ot_hash_guard, irql); // for ot_add_fileobj
	ote_addr = NULL;

	if (ot_add_fileobj(irps->DeviceObject, irps->FileObject, FILEOBJ_CONNOBJ, *ConnectionContext)) {
		DBGOUT(("tdi_event_connect: ot_add_fileobj: 0x%x\n", status));
		goto done;
	}

	ote_conn = ot_find_fileobj(irps->FileObject, &irql);
	if (!ote_conn) {
		DBGOUT(("tdi_event_connect: ot_find_fileobj(0x%x)\n", irps->FileObject));
		goto done;
	}
	
	// associate connobj with addrobj
	ote_conn->associated_fileobj = ctx->fileobj;

	if (local_addr->AddressLength != remote_addr->AddressLength) {
		// what the ...
		DBGOUT(("tdi_event_connect: different addr lengths! (%u != %u)\n",
			local_addr->AddressLength, remote_addr->AddressLength));
		goto done;
	}

	// associate remote address with connobj
	
	if (remote_addr->AddressLength > sizeof(ote_conn->remote_addr)) {
		DBGOUT(("tdi_event_connect: address too long! (%u)\n", remote_addr->AddressLength));
		goto done;
	}
	memcpy(ote_conn->remote_addr, remote_addr, remote_addr->AddressLength);

	// associate local address with connobj

	if (local_addr->AddressLength > sizeof(ote_conn->local_addr)) {
		DBGOUT(("tdi_event_connect: address too long! (%u)\n", local_addr->AddressLength));
		goto done;
	}
	memcpy(ote_conn->local_addr, local_addr, local_addr->AddressLength);

	if(!ConvertConnToSocketRecord(ote_conn, SYS_CONNECT, &log_record)) {
		DBGOUT(("tdi_event_connect: Unable to convert record!"));
		goto done;
	}

	pid = ote_conn->pid;
	fShouldLog = TRUE;
done:
	if (ote_addr || ote_conn)
		KeReleaseSpinLock(&g_ot_hash_guard, irql);

	if(fShouldLog)
		LogRecord(pid, &log_record);

	return status;
}

//----------------------------------------------------------------------------

// don't delete this "empty" event handler! we'll lost old handler address!
NTSTATUS
tdi_event_disconnect(
    IN PVOID TdiEventContext,
    IN CONNECTION_CONTEXT ConnectionContext,
    IN LONG DisconnectDataLength,
    IN PVOID DisconnectData,
    IN LONG DisconnectInformationLength,
    IN PVOID DisconnectInformation,
    IN ULONG DisconnectFlags)
{
	TDI_EVENT_CONTEXT *ctx = (TDI_EVENT_CONTEXT *)TdiEventContext;
	KIRQL irql;

	return ((PTDI_IND_DISCONNECT)(ctx->old_handler))
		(ctx->old_context, ConnectionContext, DisconnectDataLength,
		DisconnectData, DisconnectInformationLength, DisconnectInformation,
		DisconnectFlags);
}

//----------------------------------------------------------------------------

NTSTATUS
tdi_event_receive(
    IN PVOID TdiEventContext,
    IN CONNECTION_CONTEXT ConnectionContext,
    IN ULONG ReceiveFlags,
    IN ULONG BytesIndicated,
    IN ULONG BytesAvailable,
    OUT ULONG *BytesTaken,
    IN PVOID Tsdu,
    OUT PIRP *IoRequestPacket)
{
	TDI_EVENT_CONTEXT *ctx = (TDI_EVENT_CONTEXT *)TdiEventContext;
	PFILE_OBJECT connobj = ot_find_conn_ctx(ctx->fileobj, ConnectionContext);
	ot_entry_t *ote_conn = NULL;
	KIRQL irql;
	TA_ADDRESS *remote_addr, *local_addr;
	int result = FILTER_IGNORE;
	char *new_data = NULL;
	ULONG new_data_size;
	NTSTATUS status;

	ote_conn = ot_find_fileobj(connobj, &irql);
	if (!ote_conn) {
		DBGOUT(("tdi_event_receive: ot_find_fileobj(0x%x)\n", connobj));
		goto done;
	}

	local_addr = (TA_ADDRESS *)(ote_conn->local_addr);
	remote_addr = (TA_ADDRESS *)(ote_conn->remote_addr);

	DBGOUT(("tdi_event_receive: %s %x:%u -> %x:%u  (offset: %u; size: %u)\n", ote_conn->ProcessName,
		ntohl(((TDI_ADDRESS_IP *)(remote_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(remote_addr->Address))->sin_port),
		ntohl(((TDI_ADDRESS_IP *)(local_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(local_addr->Address))->sin_port),
		ote_conn->in_offset, BytesAvailable));

	// call old handler (at IRQL_DISPATCH_LEVEL)
	status = ((PTDI_IND_RECEIVE)(ctx->old_handler))
		(ctx->old_context, ConnectionContext, ReceiveFlags, BytesIndicated,
		BytesAvailable, BytesTaken, Tsdu, IoRequestPacket);

	if (status == STATUS_SUCCESS) 
		ote_conn->in_offset += BytesAvailable;
	else if (status == STATUS_MORE_PROCESSING_REQUIRED)
		ote_conn->in_offset += *BytesTaken;
done:
	if (new_data) free(new_data);
	if (ote_conn) KeReleaseSpinLock(&g_ot_hash_guard, irql);

	return status;
}

//----------------------------------------------------------------------------

NTSTATUS
tdi_event_receive_datagram(
    IN PVOID TdiEventContext,
    IN LONG SourceAddressLength,
    IN PVOID SourceAddress,
    IN LONG OptionsLength,
    IN PVOID Options,
    IN ULONG ReceiveDatagramFlags,
    IN ULONG BytesIndicated,
    IN ULONG BytesAvailable,
    OUT ULONG *BytesTaken,
    IN PVOID Tsdu,
    OUT PIRP *IoRequestPacket)
{
	TDI_EVENT_CONTEXT *ctx = (TDI_EVENT_CONTEXT *)TdiEventContext;
	ot_entry_t *ote_addr = NULL;
	KIRQL irql;
	TA_ADDRESS *remote_addr, *local_addr;
	int result = FILTER_IGNORE;
	char *new_data = NULL;
	ULONG new_data_size;
	NTSTATUS status;

	ote_addr = ot_find_fileobj(ctx->fileobj, &irql);
	if (!ote_addr) {
		DBGOUT(("tdi_event_receive_datagram: ot_find_fileobj(0x%x)\n", ctx->fileobj));
		goto done;
	}

	local_addr = (TA_ADDRESS *)(ote_addr->local_addr);
	remote_addr = ((TRANSPORT_ADDRESS *)SourceAddress)->Address;

	DBGOUT(("tdi_event_receive_datagram: %s %x:%u -> %x:%u  (offset: %u; size: %u)\n", ote_addr->ProcessName,
		ntohl(((TDI_ADDRESS_IP *)(remote_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(remote_addr->Address))->sin_port),
		ntohl(((TDI_ADDRESS_IP *)(local_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(local_addr->Address))->sin_port),
		ote_addr->in_offset, BytesAvailable));

	// call old handler (at IRQL_DISPATCH_LEVEL)
	status = ((PTDI_IND_RECEIVE_DATAGRAM)(ctx->old_handler))
		(ctx->old_context, SourceAddressLength, SourceAddress, OptionsLength,
		Options, ReceiveDatagramFlags, BytesIndicated, BytesAvailable, BytesTaken,
		Tsdu, IoRequestPacket);

	if (status == STATUS_SUCCESS) ote_addr->in_offset += BytesAvailable;
	else if (status == STATUS_MORE_PROCESSING_REQUIRED)
		ote_addr->in_offset += *BytesTaken;

done:
	if (new_data) free(new_data);
	if (ote_addr) KeReleaseSpinLock(&g_ot_hash_guard, irql);

	return status;
}

//----------------------------------------------------------------------------

NTSTATUS
tdi_event_receive_expedited(
    IN PVOID TdiEventContext,
    IN CONNECTION_CONTEXT ConnectionContext,
    IN ULONG ReceiveFlags,
    IN ULONG BytesIndicated,
    IN ULONG BytesAvailable,
    OUT ULONG *BytesTaken,
    IN PVOID Tsdu,
    OUT PIRP *IoRequestPacket)
{
	TDI_EVENT_CONTEXT *ctx = (TDI_EVENT_CONTEXT *)TdiEventContext;
	PFILE_OBJECT connobj = ot_find_conn_ctx(ctx->fileobj, ConnectionContext);
	ot_entry_t *ote_conn = NULL;
	KIRQL irql;
	TA_ADDRESS *remote_addr, *local_addr;
	int result = FILTER_IGNORE;
	char *new_data = NULL;
	ULONG new_data_size;
	NTSTATUS status;

	ote_conn = ot_find_fileobj(connobj, &irql);
	if (!ote_conn) {
		DBGOUT(("tdi_event_receive_expedited: ot_find_fileobj(0x%x)\n", connobj));
		goto done;
	}

	local_addr = (TA_ADDRESS *)(ote_conn->local_addr);
	remote_addr = (TA_ADDRESS *)(ote_conn->remote_addr);

	DBGOUT(("tdi_event_receive_expedited: %s %x:%u -> %x:%u  (offset: %u; size: %u)\n", ote_conn->ProcessName,
		ntohl(((TDI_ADDRESS_IP *)(remote_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(remote_addr->Address))->sin_port),
		ntohl(((TDI_ADDRESS_IP *)(local_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(local_addr->Address))->sin_port),
		ote_conn->in_oob_offset, BytesAvailable));

	// call old handler (at IRQL_DISPATCH_LEVEL)
	status = ((PTDI_IND_RECEIVE_EXPEDITED)(ctx->old_handler))
		(ctx->old_context, ConnectionContext, ReceiveFlags, BytesIndicated,
		BytesAvailable, BytesTaken, Tsdu, IoRequestPacket);

	if (status == STATUS_SUCCESS) ote_conn->in_oob_offset += BytesAvailable;
	else if (status == STATUS_MORE_PROCESSING_REQUIRED)
		ote_conn->in_oob_offset += *BytesTaken;

done:
	if (new_data) free(new_data);
	if (ote_conn) KeReleaseSpinLock(&g_ot_hash_guard, irql);

	return status;
}

//----------------------------------------------------------------------------

NTSTATUS
tdi_event_chained_receive(
    IN PVOID TdiEventContext,
    IN CONNECTION_CONTEXT ConnectionContext,
    IN ULONG ReceiveFlags,
    IN ULONG ReceiveLength,
    IN ULONG StartingOffset,
    IN PMDL  Tsdu,
    IN PVOID TsduDescriptor)
{
	TDI_EVENT_CONTEXT *event_ctx = (TDI_EVENT_CONTEXT *)TdiEventContext;
	PFILE_OBJECT connobj = ot_find_conn_ctx(event_ctx->fileobj, ConnectionContext);
	ot_entry_t *ote_conn = NULL, *ote_addr = NULL;
	KIRQL irql;
	TA_ADDRESS *remote_addr, *local_addr;
	int result = FILTER_IGNORE, b_free_data = 0, b_release_mdl = 1;
	char *data = NULL, *new_data = NULL;
	ULONG data_size, new_data_size;
	PMDL mdl;
	NTSTATUS status;
	PIRP new_irp;

	ote_conn = ot_find_fileobj(connobj, &irql);
	if (!ote_conn) {
		DBGOUT(("tdi_event_receive: ot_find_fileobj\n"));
		goto done;
	}

	local_addr = (TA_ADDRESS *)(ote_conn->local_addr);
	remote_addr = (TA_ADDRESS *)(ote_conn->remote_addr);

	DBGOUT(("tdi_event_chained_receive: %s %x:%u -> %x:%u  (offset: %u; size: %u)\n", ote_conn->ProcessName,
		ntohl(((TDI_ADDRESS_IP *)(remote_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(remote_addr->Address))->sin_port),
		ntohl(((TDI_ADDRESS_IP *)(local_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(local_addr->Address))->sin_port),
		ote_conn->in_offset, ReceiveLength));
	
	// call old handler (at IRQL_DISPATCH_LEVEL)
	status = ((PTDI_IND_CHAINED_RECEIVE)(event_ctx->old_handler))
		(event_ctx->old_context, ConnectionContext, ReceiveFlags, ReceiveLength,
		StartingOffset, Tsdu, TsduDescriptor);

	if (status == STATUS_SUCCESS || status == STATUS_PENDING) {
		ote_conn->in_offset += ReceiveLength;
		b_release_mdl = 0;
	}

done:
	if (b_release_mdl) TdiReturnChainedReceives(&TsduDescriptor, 1);
	
	if (ote_conn) KeReleaseSpinLock(&g_ot_hash_guard, irql);
	if (b_free_data && data) free(data);
	if (new_data) free(new_data);

	return status;
}

//----------------------------------------------------------------------------

NTSTATUS
tdi_event_chained_receive_datagram(
    IN PVOID TdiEventContext,
    IN LONG SourceAddressLength,
    IN PVOID SourceAddress,
    IN LONG OptionsLength,
    IN PVOID Options,
    IN ULONG ReceiveDatagramFlags,
    IN ULONG ReceiveDatagramLength,
    IN ULONG StartingOffset,
    IN PMDL  Tsdu,
    IN PVOID TsduDescriptor)
{
	TDI_EVENT_CONTEXT *event_ctx = (TDI_EVENT_CONTEXT *)TdiEventContext;
	ot_entry_t *ote_addr = NULL;
	KIRQL irql;
	TA_ADDRESS *remote_addr, *local_addr;
	int result = FILTER_IGNORE, b_free_data = 0, b_release_mdl = 1;
	char *data = NULL, *new_data = NULL;
	ULONG data_size, new_data_size;
	PMDL mdl;
	NTSTATUS status;
	PIRP new_irp;

	ote_addr = ot_find_fileobj(event_ctx->fileobj, &irql);
	if (!ote_addr) {
		DBGOUT(("tdi_event_receive_datagram: ot_find_fileobj\n"));
		goto done;
	}

	local_addr = (TA_ADDRESS *)(ote_addr->local_addr);
	remote_addr = ((TRANSPORT_ADDRESS *)SourceAddress)->Address;

	DBGOUT(("tdi_event_chained_receive_datagram: %s %x:%u -> %x:%u  (offset: %u; size: %u)\n", ote_addr->ProcessName,
		ntohl(((TDI_ADDRESS_IP *)(remote_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(remote_addr->Address))->sin_port),
		ntohl(((TDI_ADDRESS_IP *)(local_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(local_addr->Address))->sin_port),
		ote_addr->in_offset, ReceiveDatagramLength));

	// call old handler (at IRQL_DISPATCH_LEVEL)
	status = ((PTDI_IND_CHAINED_RECEIVE_DATAGRAM)(event_ctx->old_handler))
			(event_ctx->old_context, SourceAddressLength, SourceAddress, OptionsLength,
			Options, ReceiveDatagramFlags, ReceiveDatagramLength, StartingOffset,
			Tsdu, TsduDescriptor);

	if (status == STATUS_SUCCESS || status == STATUS_PENDING) {
		ote_addr->in_offset += ReceiveDatagramLength;
		b_release_mdl = 0;
	}

done:
	if (b_release_mdl) TdiReturnChainedReceives(&TsduDescriptor, 1);
	
	if (ote_addr) KeReleaseSpinLock(&g_ot_hash_guard, irql);
	if (b_free_data && data) free(data);
	if (new_data) free(new_data);

	return status;
}

//----------------------------------------------------------------------------

NTSTATUS
tdi_event_chained_receive_expedited(
    IN PVOID TdiEventContext,
    IN CONNECTION_CONTEXT ConnectionContext,
    IN ULONG ReceiveFlags,
    IN ULONG ReceiveLength,
    IN ULONG StartingOffset,
    IN PMDL  Tsdu,
    IN PVOID TsduDescriptor)
{
	TDI_EVENT_CONTEXT *event_ctx = (TDI_EVENT_CONTEXT *)TdiEventContext;
	PFILE_OBJECT connobj = ot_find_conn_ctx(event_ctx->fileobj, ConnectionContext);
	ot_entry_t *ote_conn = NULL, *ote_addr = NULL;
	KIRQL irql;
	TA_ADDRESS *remote_addr, *local_addr;
	int result = FILTER_IGNORE, b_free_data = 0;
	char *data = NULL, *new_data = NULL;
	ULONG data_size, new_data_size;
	PMDL mdl;
	NTSTATUS status;

	ote_conn = ot_find_fileobj(connobj, &irql);
	if (!ote_conn) {
		DBGOUT(("tdi_event_receive_expedited: ot_find_fileobj\n"));
		goto done;
	}

	local_addr = (TA_ADDRESS *)(ote_conn->local_addr);
	remote_addr = (TA_ADDRESS *)(ote_conn->remote_addr);

	DBGOUT(("tdi_event_receive_expedited: %s %x:%u -> %x:%u  (offset: %u; size: %u)\n", ote_conn->ProcessName,
		ntohl(((TDI_ADDRESS_IP *)(remote_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(remote_addr->Address))->sin_port),
		ntohl(((TDI_ADDRESS_IP *)(local_addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(local_addr->Address))->sin_port),
		ote_conn->in_oob_offset, ReceiveLength));

	// call old handler (at IRQL_DISPATCH_LEVEL)
	status = ((PTDI_IND_CHAINED_RECEIVE_EXPEDITED)(event_ctx->old_handler))
		(event_ctx->old_context, ConnectionContext, ReceiveFlags, ReceiveLength,
		StartingOffset, Tsdu, TsduDescriptor);

	if (status == STATUS_SUCCESS || status == STATUS_PENDING)
		ote_conn->in_oob_offset += ReceiveLength;

done:	
	if (ote_conn) KeReleaseSpinLock(&g_ot_hash_guard, irql);
	if (data) free(data);
	if (new_data) free(new_data);

	return status;
}

/*---[ utility functions ]---*/

void *tdi_alloc(u_long size)
{
	return malloc_np(size);
}

// get linear data buffer from MDL or MDL chain (may be free needed)
char *get_mdl_data(PMDL mdl_data, ULONG *size, int *b_free)
{
	PMDL mdl;
	char *data;
	ULONG data_size, data_offset;

	if (!mdl_data->Next) {
		// no chain
		*size = mdl_data->ByteCount;
		*b_free = 0;
		return MmGetSystemAddressForMdl(mdl_data);
	}

	data_size = 0;
    for (mdl = mdl_data; mdl; mdl = mdl->Next) data_size += mdl->ByteCount;

	data = (char *)malloc_np(data_size);
	if (!data) {
		DBGOUT(("get_mdl_data: malloc_np\n"));
		return NULL;
	}

    data_offset = 0;
    for (mdl = mdl_data; mdl; mdl = mdl->Next) {
        memcpy(data + data_offset, MmGetSystemAddressForMdl(mdl), mdl->ByteCount);
        data_offset += mdl->ByteCount;
    }

	*size = data_size;
	*b_free = 1;

	return data;
}

// write data in MDL or in MDL chain
ULONG write_mdl(PMDL mdl_data, const char *data, ULONG size)
{
	PMDL mdl;
	ULONG data_offset;

    data_offset = 0;
    for (mdl = mdl_data; mdl; mdl = mdl->Next) {
		if (size - data_offset <= mdl->ByteCount) {
	        memcpy(MmGetSystemAddressForMdl(mdl), data + data_offset, size - data_offset);
			data_offset = size;
			break;
		}
		memcpy(MmGetSystemAddressForMdl(mdl), data + data_offset, mdl->ByteCount);
		data_offset += mdl->ByteCount;
	}

	return data_offset;
}

struct delayed_ucn_param {
	WORK_QUEUE_ITEM	item;
	PDEVICE_OBJECT	devobj;
	PFILE_OBJECT	fileobj;
};

void
delayed_ucn(PVOID p)
{
	struct delayed_ucn_param *ucn_param = (struct delayed_ucn_param *)p;

	update_conn_info(ucn_param->devobj, ucn_param->fileobj);

	free(ucn_param);
}

/* query local address and port for connection */
void
update_conn_info(PDEVICE_OBJECT devobj, PFILE_OBJECT connobj)
{
	PIRP query_irp;
	PMDL mdl = NULL;
	struct uci_param *uci_param = NULL;

	// MUST be executed at PASSIVE_LEVEL

	if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
		// do it a bit later :-)
		struct delayed_ucn_param *ucn_param = (struct delayed_ucn_param *)malloc_np(sizeof(*ucn_param));
		if (ucn_param != NULL) {

			memset(ucn_param, 0, sizeof(*ucn_param));

			ucn_param->devobj = devobj;
			ucn_param->fileobj = connobj;

			ExInitializeWorkItem(&ucn_param->item, delayed_ucn, ucn_param);
			ExQueueWorkItem(&ucn_param->item, DelayedWorkQueue);	// DelayedWorkQueue a good value?

		}
		return;
	}

	query_irp = TdiBuildInternalDeviceControlIrp(TDI_QUERY_INFORMATION, devobj, connobj, NULL, NULL);
	if (query_irp == NULL) {
		DBGOUT(("update_conn_info: TdiBuildInternalDeviceControlIrp!\n"));
		goto done;
	}

	uci_param = (struct uci_param *)malloc_np(sizeof(*uci_param) + TDI_ADDRESS_INFO_MAX);
	if (uci_param == NULL) {
		DBGOUT(("update_conn_info: malloc_np!\n"));
		goto done;
	}

	memset(uci_param, 0, sizeof(*uci_param) + TDI_ADDRESS_INFO_MAX);
	uci_param->connobj = connobj;

	mdl = IoAllocateMdl(uci_param->address, TDI_ADDRESS_INFO_MAX, FALSE, FALSE, NULL);
	if (mdl == NULL) {
		DBGOUT(("update_conn_info: IoAllocateMdl!\n"));
		goto done;
	}
	MmBuildMdlForNonPagedPool(mdl);

	TdiBuildQueryInformation(query_irp, devobj, connobj,
		update_conn_info_complete, uci_param,
		TDI_QUERY_ADDRESS_INFO, mdl);

	IoCallDriver(devobj, query_irp);

	query_irp = NULL;
	mdl = NULL;
	uci_param = NULL;

done:
	// cleanup
	if (mdl != NULL)
		IoFreeMdl(mdl);
	if (uci_param != NULL)
		ExFreePool(uci_param);
	if (query_irp != NULL)
		IoCompleteRequest(query_irp, IO_NO_INCREMENT);
}

NTSTATUS
update_conn_info_complete(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context)
{
	struct uci_param *param = (struct uci_param *)Context;
	TA_ADDRESS *addr = ((TDI_ADDRESS_INFO *)(param->address))->Address.Address;
	NTSTATUS status;
	KIRQL irql;
	ot_entry_t *ote = NULL;

	DBGOUT(("update_conn_info_complete: address: %x:%u %d\n", 
		ntohl(((TDI_ADDRESS_IP *)(addr->Address))->in_addr),
		ntohs(((TDI_ADDRESS_IP *)(addr->Address))->sin_port), addr->AddressLength));

	// save address

	ote = ot_find_fileobj(param->connobj, &irql);
	if (!ote) {
		DBGOUT(("update_conn_info_complete: ot_find_fileobj(0x%x)\n", param->connobj));
		status = STATUS_OBJECT_NAME_NOT_FOUND;
		goto done;
	}

	if (addr->AddressLength > sizeof(ote->local_addr)) {
		DBGOUT(("update_conn_info_complete: address too long! (%u)\n",
			addr->AddressLength));
		status = STATUS_BUFFER_OVERFLOW;
		goto done;
	}
	memcpy(ote->local_addr, addr, addr->AddressLength);

	status = STATUS_SUCCESS;
done:
	// cleanup MDL to avoid unlocking pages from NonPaged pool
	if (Irp->MdlAddress != NULL) {
		IoFreeMdl(Irp->MdlAddress);
		Irp->MdlAddress = NULL;
	}

	free(param);

	if(ote)
		KeReleaseSpinLock(&g_ot_hash_guard, irql);

	return status;
}

BOOL LogRecord(const ULONG pid, const struct sbk_sock_rec *pRecord)
{
	ProcessData proc;
	NTSTATUS status;

	if(!pRecord)
		return FALSE;

	RtlZeroMemory(&proc, sizeof(proc));
	proc.ulProcessID = pid;

	if(!GetProcessInfo(&proc))
		return FALSE;

	DBGOUT(("Sending Socket Record. PPID %d, PID %d Call %d Src 0x%08X Dst 0x%08X dport %d sport %d", proc.ulParentPID, proc.ulProcessID, pRecord->call, ntohl(pRecord->sip), ntohl(pRecord->dip), ntohl(pRecord->dport), ntohl(pRecord->sport)));

	status = LogData(SEBEK_TYPE_SOCKET, &proc, (PBYTE)pRecord, sizeof(*pRecord));
	FreeProcessData(&proc);

	return status == STATUS_SUCCESS;
}

NTSTATUS tdi_event_error(IN PVOID TdiEventContext, IN NTSTATUS Status)
{
	DBGOUT(("tdi_event_error: contect %08x Status: %08X", TdiEventContext, Status));
	return STATUS_SUCCESS;
}

NTSTATUS tdi_event_errorex(IN PVOID TdiEventContext, IN NTSTATUS Status, IN PVOID Buffer)
{
	DBGOUT(("tdi_event_errorex: contect %08x Status: %08X", TdiEventContext, Status));
	return STATUS_SUCCESS;
}
#endif