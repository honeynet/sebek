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

#ifndef SYSTEM_SERVICE_H
#define SYSTEM_SERVICE_H

#include <ntddk.h>
#include "debug.h"

#if _MSC_VER > 1000
#pragma once
#endif

extern ULONG s_ulCallCount;

// Macros to disable XP protection.
#define WPOFF() \
	_asm mov eax, cr0 \
	_asm and eax, NOT 10000H \
	_asm mov cr0, eax

#define WPON() \
	_asm mov eax, cr0 \
	_asm or eax, 10000H \
	_asm mov cr0, eax


//
// System call structure/entrypoints
//
#pragma pack(push, 1)
typedef struct _SYSTEM_SERVICE_DISPATCH_TABLE {
   PULONG ServiceTable;
   PULONG ServiceCounterTable;
   ULONG  ServiceCount;
   PULONG ArgumentSizeTable;
} SYSTEM_SERVICE_DISPATCH_TABLE, *PSYSTEM_SERVICE_DISPATCH_TABLE;
#pragma pack(pop)

__declspec(dllimport) SYSTEM_SERVICE_DISPATCH_TABLE KeServiceDescriptorTable;
// Suspicious pointer-to-pointer conversion (area too small)
//lint -e826
#define SYSTEMSERVICE(_function) *(PULONG)((PUCHAR)_function+1)

NTSTATUS NTAPI KeAddSystemServiceTable(ULONG, ULONG, ULONG, ULONG, LONG);

// -------------------------------------
// System Call Hooking Support functions
//
static
PSYSTEM_SERVICE_DISPATCH_TABLE
GetShadowServiceDispatchTable(
   )
{
   int i;
   PUCHAR p;
   ULONG dwValue;

	 //lint -e611
   p = (PUCHAR)KeAddSystemServiceTable;

   for (i = 0; i < 4096; i++, p++)
   {
      __try
      {
				// Suspicious pointer-to-pointer conversion (area too small)
				//lint -e826 
         dwValue = *((PULONG)p);
      }
      __except (EXCEPTION_EXECUTE_HANDLER)
      {
         return 0;
      }

      if (MmIsAddressValid((PVOID)dwValue))
      {
         if (memcmp((PVOID)dwValue, &KeServiceDescriptorTable, 
            sizeof(KeServiceDescriptorTable)) == 0)
         {
            continue;
         }

         return (PSYSTEM_SERVICE_DISPATCH_TABLE)dwValue;
      }
   }

   return 0;
}

static
BOOLEAN
SetSystemCallIndex(
   IN ULONG Index,
   IN PVOID Function,
   OUT PVOID *pPrevFunction
   )
{
   static PSYSTEM_SERVICE_DISPATCH_TABLE ShadowTablePtr = NULL;

   if (!ShadowTablePtr)
      ShadowTablePtr = GetShadowServiceDispatchTable();

	 if(!ShadowTablePtr) {
		 DBGOUT(("Unable to load shadow table!"));
		 return FALSE;
	 }
	 
	 DBGOUT(("Shadow table loaded at %08x", ShadowTablePtr));
	 
	 if (pPrevFunction)
      *((PULONG)pPrevFunction) = (ULONG)KeServiceDescriptorTable.ServiceTable[Index];
		
	__try {
		DBGOUT(("Hooking KeServiceDescriptorTable index %d with address %08x\n", Index, (LONG)Function));
		WPOFF();
		//lint -e64 -e534
		InterlockedExchange(&KeServiceDescriptorTable.ServiceTable[Index], (LONG)Function);
		WPON();
	} __except(EXCEPTION_EXECUTE_HANDLER)	{
		DBGOUT(("Unable to hook KeServiceDescriptorTable index %d with address %08x. Exception occurred.", Index, (LONG)Function));
		if(pPrevFunction)
			*((PULONG)pPrevFunction) = 0;
		return FALSE;
	}

	/*__try {
		DBGOUT(("Hooking Shadow Table index %d with address %08x\n", Index, (LONG)Function));
		InterlockedExchange(&ShadowTablePtr->ServiceTable[Index], (LONG)Function);
	} __except(EXCEPTION_EXECUTE_HANDLER)	{
		DBGOUT(("Unable to hook Shadow table index %d with address %08x. Exception occurred.", Index, (LONG)Function));
		// This worked above so it should work now without throwing an exception.
		InterlockedExchange(&KeServiceDescriptorTable.ServiceTable[Index], (LONG)*((PULONG)pPrevFunction));
		*((PULONG)pPrevFunction) = 0;
		ShadowTablePtr = NULL;
		return FALSE;
	}*/

	return TRUE;
}

#endif
