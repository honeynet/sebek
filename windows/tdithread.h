#ifndef TDITHREAD_H
#define TDITHREAD_H

#include <ntddk.h>

#define TDI_INIT_TIMEOUT 60 /* in seconds */
#define TDI_RETRY_TIMER 2 /* seconds */

extern KEVENT g_TDIThreadShutdownEvent;
extern KEVENT g_TDIThreadStartEvent;

NTKERNELAPI
NTSTATUS
ObReferenceObjectByName(
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

KSTART_ROUTINE TDIThread;
VOID TDIThread(PVOID pData);

#endif