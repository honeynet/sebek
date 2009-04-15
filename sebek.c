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

/* This code is mostly from http://ntdev.h1.ru/ndis_fw.html but was put into public domain by Vlad */

#include <ntddk.h>
#include "sebek.h"
#include "util.h"

#include "adapters.h"
#include "av.h"
#include "memtrack.h"
#include "nt.h"
#include "pe.h"
#include "consolespy.h"
#include "antidetection.h"
#include "logging.h"
#include "exports.h"
#include "tdithread.h"
#include "tdi_hook.h"

/* globals */

/** macro do build entry for hooked function array g_hook_fn */
#define HOOK_FN_ENTRY(name) \
	{#name, NULL, new_##name}

struct hook_fn g_hook_fn[MAX_HOOK_FN] = {
	// see hooked_fn.c
	HOOK_FN_ENTRY(NdisRegisterProtocol),
	HOOK_FN_ENTRY(NdisDeregisterProtocol),
	HOOK_FN_ENTRY(NdisOpenAdapter),
	HOOK_FN_ENTRY(NdisCloseAdapter)
};

static PDEVICE_OBJECT g_pDevControl = NULL;

// Number of active calls
ULONG s_ulCallCount;

// The driver name is the filename of the driver. I.E: SEBEK.SYS
CHAR g_DriverName[12];
UINT g_uiDriverNameLen = 0;

// The Service name is the name of the kernel service in the registry. I.E: sebek
CHAR g_ServiceName[12];
UINT g_uiServiceNameLen = 0;

UNICODE_STRING g_ImagePath;

//extern BOOLEAN s_LoggingInit;
//extern BOOLEAN s_ConsoleSpyInit;
//extern BOOLEAN s_AntiDetectionInit;
KEVENT g_TDIThreadStartEvent;

PETHREAD g_TDIThreadObject = NULL;

/* prototypes */

NTSTATUS		DeviceDispatch(IN CONST PDEVICE_OBJECT DeviceObject, IN PIRP irp);
VOID			OnUnload(IN PDRIVER_OBJECT);

NTSTATUS		hook_ndis(int unhook);

void			*find_system_dll(const char *name);
void			*fix_export(char *base, const char *fn, const void *new_fn);

BOOLEAN			replace_value_safe(ULONG *addr, ULONG value);

/**
 * Main driver function
 */
NTSTATUS
DriverEntry(IN PDRIVER_OBJECT theDriverObject,
            IN const PUNICODE_STRING theRegistryPath)
{
	NTSTATUS status;
	int i;
	ANSI_STRING aImagePath;
	PCHAR p = NULL;
	HANDLE hThread;

 	memtrack_init();
	init_adapter_list();
	GetProcessNameOffset();
	
	if(!theRegistryPath || !theDriverObject)
		return STATUS_UNSUCCESSFUL;
	
	RtlZeroMemory(&g_ImagePath, sizeof(g_ImagePath));
	status = RegGetSz(RTL_REGISTRY_ABSOLUTE, theRegistryPath->Buffer, L"ImagePath", &g_ImagePath);
	if(status != STATUS_SUCCESS) {
		return status;
	}

	RtlUnicodeStringToAnsiString(&aImagePath, &g_ImagePath, TRUE);

  p = _strrchr (aImagePath.Buffer, '\\');
	if(!p) {
		RtlFreeAnsiString(&aImagePath);
		return STATUS_UNSUCCESSFUL;
	}
	
  p++;

	/* We do the following to optimize our antidetection */ 
	RtlZeroMemory(g_DriverName, sizeof(g_DriverName));
	g_uiDriverNameLen = min(strlen(p), sizeof(g_DriverName));
	strncpy(g_DriverName, p, g_uiDriverNameLen);
	g_uiConfigProcNameLen = strlen(g_ConfigProcName);

	RtlZeroMemory(g_ServiceName, sizeof(g_ServiceName));
	g_uiServiceNameLen = min(g_uiDriverNameLen - 4, sizeof(g_ServiceName)/sizeof(g_ServiceName[0]) - 1); // remove the .SYS
	strncpy(g_ServiceName, g_DriverName, g_uiServiceNameLen);
	/* End Optimization */

	RtlFreeAnsiString(&aImagePath);
		
	DBGOUT(("DriverName: %s (%d)", g_DriverName, g_uiDriverNameLen));
	DBGOUT(("ServiceName: %s (%d)", g_ServiceName, g_uiServiceNameLen));
	DBGOUT(("ConfigProcName: %s (%d)", g_ConfigProcName, g_uiConfigProcNameLen));
	DBGOUT(("ImagePath: %S", g_ImagePath.Buffer));

	status = init_av();
	if (status != STATUS_SUCCESS) {
		DBGOUT(("init_av: 0x%x\n", status));
		goto done;
	}

	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
		theDriverObject->MajorFunction[i] = DeviceDispatch;

	// register UnLoad procedure
	theDriverObject->DriverUnload = OnUnload;

	status = hook_ndis(FALSE);
	if(status != STATUS_SUCCESS) {
		DBGOUT(("DriverEntry: hook_ndis: 0x%x!\n", status));
		goto done;
	}

#ifdef ENABLE_TDIHOOK
	// Create our TDI initialization thread.
	KeInitializeEvent(&g_TDIThreadStartEvent, NotificationEvent, FALSE);

	status = PsCreateSystemThread(&hThread, (ACCESS_MASK) 0L, NULL, NULL, NULL, (PKSTART_ROUTINE)&TDIThread, (PVOID)NULL);
	if(!NT_SUCCESS(status)) {
		DBGOUT(("Unable to create GUI communications thread!\n"));
		goto done;
	}

	status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, NULL, KernelMode, &g_TDIThreadObject, 0);
	if(!NT_SUCCESS(status)) {
		ZwClose(hThread);
		goto done;
	}  

	ZwClose(hThread);
#endif

	status = InitConsoleSpy(OnConsoleWrite, OnConsoleRead);
	if(status != STATUS_SUCCESS) {
		DBGOUT(("DriverEntry: InitConsoleSpy: 0x%x!\n", status));
		goto done;
	}


	status = InitAntiDetection(theDriverObject);
	if(status != STATUS_SUCCESS) {
		DBGOUT(("DriverEntry: InitAntiDetection: 0x%x!\n", status));
		goto done;
	}

done:
	if (status != STATUS_SUCCESS)
		OnUnload(theDriverObject);

	return status;
}

/**
 * Dispatch function.
 * Works with i/o controls for control device
 */
NTSTATUS
DeviceDispatch(IN const PDEVICE_OBJECT DeviceObject, IN PIRP irp)
{
	NTSTATUS status;

	if(!irp)
		return STATUS_UNSUCCESSFUL;
	
	// set irp with defaults
	irp->IoStatus.Information = 0;

	if(DeviceObject == g_pDevControl) { // This is our driver
		PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(irp);

		switch (irps->MajorFunction) {
		case IRP_MJ_CREATE:
		case IRP_MJ_CLEANUP:
		case IRP_MJ_CLOSE:
			status = STATUS_SUCCESS;
			break;
		default:
			status = STATUS_NOT_SUPPORTED;
			}
	} else
		status = STATUS_NOT_SUPPORTED;

	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}

/*
 * Unload procedure
 * Driver can't be unloaded due to security reasons.
 * This function only for memory leak testing
 */
VOID
OnUnload(IN PDRIVER_OBJECT DriverObject)
{
	// Wait for all active calls to complete (Could be a while ...
  //  we should yield thread execution)
  while (s_ulCallCount)
      ;
	
#ifdef ENABLE_TDIHOOK
	KeSetEvent(&g_TDIThreadShutdownEvent, 0, FALSE);
	if(g_TDIThreadObject) {
		KeWaitForSingleObject(g_TDIThreadObject, Executive, KernelMode, FALSE, NULL);
		ObDereferenceObject(g_TDIThreadObject);
	}
#endif

	if(s_LoggingInit)
		UninitLogging();
	
	if(s_ConsoleSpyInit)
		UninitConsoleSpy();

	if(s_AntiDetectionInit)
		UninitAntiDetection();
		
#ifdef ENABLE_TDIHOOK
	UnloadTDIHook();
#endif

	// unhook NDIS
	hook_ndis(TRUE);

	free_av();
	free_adapter_list();

	memtrack_free();
ExFreePool(g_ImagePath.Buffer);
}

/**
 * Hook or unhook NDIS functions
 * @param	unhook				if (!unhook) hook; else unhook;
 * @retval	STATUS_SUCCESS		no error
 */
NTSTATUS
hook_ndis(int unhook)
{
	void *ndis_sys;
	int i;

	// 1. find ndis.sys
	ndis_sys = find_system_dll("NDIS.sys");
	if (ndis_sys == NULL) {
		DBGOUT(("hook_ndis: find_system_dll!\n"));
		return STATUS_OBJECT_NAME_NOT_FOUND;
	}

	// 2. (un)hook all of the functions
	for (i = 0; i < MAX_HOOK_FN; i++) {
		if (!unhook) {
			void *old_fn = fix_export((char *)ndis_sys, g_hook_fn[i].name, g_hook_fn[i].new_fn);

			if (old_fn == NULL) {
				DBGOUT(("hook_ndis: fix_export!\n"));

				// replace them back!
				hook_ndis(TRUE);

				return STATUS_OBJECT_NAME_NOT_FOUND;
			}
			
			DBGOUT(("hook_ndis: %s: old: 0x%x new: 0x%x\n", 
				g_hook_fn[i].name,
				old_fn,
				g_hook_fn[i].new_fn));

			g_hook_fn[i].old_fn = old_fn;
		
		} else {
			if (g_hook_fn[i].old_fn != NULL)
				fix_export((char *)ndis_sys, g_hook_fn[i].name, g_hook_fn[i].old_fn);
		}
	}

	return STATUS_SUCCESS;
}

/**
 * Find base address of system module.
 * Used to find base address of ndis.sys
 * @param	name	name of system module
 * @return			base address of system module
 * @retval	NULL	system module not found
 */
void *
find_system_dll(const char *name)
{
	ULONG i, n, *q;
	PSYSTEM_MODULE_INFORMATION p;
	void *base;

	ZwQuerySystemInformation(SystemModuleInformation, &n, 0, &n);
	q = (ULONG *)ExAllocatePool(PagedPool, n);
	ZwQuerySystemInformation(SystemModuleInformation, q, n * sizeof (*q), 0);
	
	p = (PSYSTEM_MODULE_INFORMATION)(q + 1);
	base = NULL;
	for (i = 0; i < *q; i++) {
		if (_stricmp( p[i].ImageName + p[i].ModuleNameOffset, name) == 0) {
			base = p[i].Base;
			DBGOUT(("find_system_dll: %s; base = 0x%x; size = 0x%x\n", name, base, p[i].Size));
			break;
		}
	}
		
	ExFreePool(q);
	return base;
}

/**
 * Fix export table in module
 * @param	base	base address of module
 * @param	fn		name of function
 * @param	new_fn	new address of function
 * @return			old address of function
 */
void *
fix_export(char *base, const char *fn, const void *new_fn)
{
	PIMAGE_DOS_HEADER dos_hdr;
	PIMAGE_NT_HEADERS nt_hdr;
	PIMAGE_EXPORT_DIRECTORY export_dir;
	ULONG *fn_name, *fn_addr, i;

	if(!base)
		return NULL;

	dos_hdr = (PIMAGE_DOS_HEADER)base;

	if (dos_hdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	nt_hdr = (PIMAGE_NT_HEADERS)(base + dos_hdr->e_lfanew);

	export_dir = (PIMAGE_EXPORT_DIRECTORY)(base + nt_hdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	fn_name = (ULONG *)(base + export_dir->AddressOfNames);
	fn_addr = (ULONG *)(base + export_dir->AddressOfFunctions);

	for (i = 0; i < export_dir->NumberOfNames; i++, fn_name++, fn_addr++) {
		if (strcmp(fn, base + *fn_name) == 0) {
			void *old_addr = base + *fn_addr;

				// replace value safe
				replace_value_safe(fn_addr, (char *)new_fn - base);

			return old_addr;
		}
	}

	return NULL;
}

/**
 * Replace ULONG value even if memory page has read only attributes
 * @param	addr	address of ULONG
 * @param	value	ULONG value
 * @retval	TRUE	no errors
 */
BOOLEAN
replace_value_safe(ULONG *addr, ULONG value)
{
	MDL *mdl;
	ULONG *virt_addr;

	mdl = IoAllocateMdl(addr, sizeof(value), FALSE, FALSE, NULL);
	if (mdl == NULL)
		return FALSE;

	__try {

		MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);

	} __except(EXCEPTION_EXECUTE_HANDLER) {
		DBGOUT(("replace_value_safe: MmProbeAndLockPages!\n"));
		return FALSE;
	}

	virt_addr = (ULONG *)MmGetSystemAddressForMdlSafe(mdl, HighPagePriority);

	InterlockedExchange(virt_addr, value);

	MmUnlockPages(mdl);
	IoFreeMdl(mdl);
	return TRUE;
}
/*@}*/
