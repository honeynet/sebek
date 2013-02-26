#ifndef TIB_H
#define TIB_H

/*
 *	Based off of tib.h from Matt Pietrek in Microsoft Systems Journal "Under the Hood", May 1996	
 */

#pragma pack(1)
#include "windef.h"
/*
#ifndef DWORD
#define DWORD ULONG
#endif

#ifndef WORD
#define WORD USHORT
#endif

typedef WORD *PWORD;
*/
typedef struct _RTL_CRITICAL_SECTION_DEBUG {
	WORD   Type;
	WORD   CreatorBackTraceIndex;
	struct _RTL_CRITICAL_SECTION *CriticalSection;
	LIST_ENTRY ProcessLocksList;
	DWORD EntryCount;
	DWORD ContentionCount;
	DWORD Spare[ 2 ];
} RTL_CRITICAL_SECTION_DEBUG, *PRTL_CRITICAL_SECTION_DEBUG, RTL_RESOURCE_DEBUG, *PRTL_RESOURCE_DEBUG;

typedef struct _RTL_CRITICAL_SECTION {
	PRTL_CRITICAL_SECTION_DEBUG DebugInfo;

	//
	//  The following three fields control entering and exiting the critical
	//  section for the resource
	//

	LONG LockCount;
	LONG RecursionCount;
	HANDLE OwningThread;        // from the thread's ClientId->UniqueThread
	HANDLE LockSemaphore;
	ULONG_PTR SpinCount;        // force size on 64-bit systems when packed
} RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION;

typedef RTL_CRITICAL_SECTION CRITICAL_SECTION;
typedef PRTL_CRITICAL_SECTION PCRITICAL_SECTION;

typedef struct _MODULE_ITEM {
/*000*/ LIST_ENTRY     ModuleListLoadOrder;
/*008*/ LIST_ENTRY     ModuleListMemoryOrder;
/*010*/ LIST_ENTRY     ModuleListInitOrder;
/*018*/ DWORD          ImageBase;
/*01C*/ DWORD          EntryPoint;
/*020*/ DWORD          ImageSize;
/*024*/ UNICODE_STRING PathFileName;
/*02C*/ UNICODE_STRING FileName;
/*034*/ ULONG          ModuleFlags;
/*038*/ WORD           LoadCount;
/*03A*/ WORD           Fill;
/*03C*/ DWORD          dw3c;
/*040*/ DWORD          dw40;
/*044*/ DWORD          TimeDateStamp;
/*048*/ } MODULE_ITEM, *PMODULE_ITEM;

typedef struct _PROCESS_MODULE_INFO {
	/*000*/ DWORD      Size;
	/*004*/ DWORD      Initalized;
	/*008*/ HANDLE     SsHandle;
	/*00C*/ LIST_ENTRY ModuleListLoadOrder;   // see MODULE_ITEM
	/*014*/ LIST_ENTRY ModuleListMemoryOrder; // see MODULE_ITEM
	/*018*/ LIST_ENTRY ModuleListInitOrder;   // see MODULE_ITEM
	/*020*/ } PROCESS_MODULE_INFO, *PPROCESS_MODULE_INFO;

#define PP_NORMALIZED 0x1L 

typedef struct _PROCESS_PARAMETERS {
	/*000*/ DWORD          MaximumLength;
	/*004*/ DWORD          Length;
	/*008*/ DWORD          Flags; // PP_NORMALIZED (RtlNormalizeProcessParams)
	/*00C*/ DWORD          DebugFlags;
	/*010*/ HANDLE         ConsoleHandle;
	/*014*/ DWORD          ConsoleFlags;
	/*018*/ HANDLE         StandardInput;
	/*01C*/ HANDLE         StandardOutput;
	/*020*/ HANDLE         StandardError;
	/*024*/ UNICODE_STRING CurrentDirectory;
	/*02C*/ HANDLE         hCurrentDirectory;
	/*030*/ UNICODE_STRING DllPath;
	/*038*/ UNICODE_STRING ImagePathName;
	/*040*/ UNICODE_STRING CommandLine;
	/*048*/ PVOID          Environment;
	/*04C*/ DWORD          StartingX;
	/*050*/ DWORD          StartingY;
	/*054*/ DWORD          CountX;
	/*058*/ DWORD          CountY;
	/*060*/ DWORD          CountCharsX;
	/*064*/ DWORD          CountCharsY;
	/*068*/ DWORD          FillAttribute;
	/*06C*/ DWORD          WindowFlags;
	/*070*/ DWORD          ShowWindowFlags;
	/*074*/ UNICODE_STRING WindowTitle;
	/*07C*/ UNICODE_STRING DesktopInfo;
	/*084*/ UNICODE_STRING ShellInfo;
	/*08C*/ UNICODE_STRING RuntimeData;
	/*094*/ } PROCESS_PARAMETERS, *PPROCESS_PARAMETERS;

typedef void (*PEB_LOCK_ROUTINE)(PVOID);

typedef struct _PEB_FREE_BLOCK {
	struct _PEB_FREE_BLOCK *Next;
	DWORD                  Size;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

typedef struct _PEB {
/*000*/ BOOLEAN              InheritedAddressSpace;
/*001*/ BOOLEAN              ReadImageFileExecOptions;
/*002*/ BOOLEAN              BeingDebugged;
/*003*/ BOOLEAN              SpareBool; // alloc size
/*004*/ HANDLE               Mutant;
/*008*/ PVOID                SectionBaseAddress;
/*00C*/ PPROCESS_MODULE_INFO ProcessModuleInfo;
/*010*/ PPROCESS_PARAMETERS  ProcessParameters;
/*014*/ DWORD                SubSystemData;
/*018*/ HANDLE               ProcessHeap;
/*01C*/ PCRITICAL_SECTION    FastPebLock;
/*020*/ PEB_LOCK_ROUTINE     AcquireFastPebLockRoutine;
/*024*/ PEB_LOCK_ROUTINE     ReleaseFastPebLockRoutine;
/*028*/ DWORD                EnvironmentUpdateCount;
/*02C*/ PVOID                *User32DispatchRoutine;
/*030*/ PVOID                EventLogSection;
/*034*/ PVOID                EventLog;
/*038*/ PPEB_FREE_BLOCK      FreeList;
/*03C*/ DWORD                TlsBitMapSize;
/*040*/ PRTL_BITMAP          TlsBitMap;
/*044*/ LARGE_INTEGER        TlsBitMapData;
/*04C*/ PVOID                ReadOnlySharedMemoryBase;
/*050*/ PVOID                ReadOnlySharedMemoryHeap;
/*054*/ PVOID                ReadOnlyStaticServerData;
/*058*/ PVOID                InitAnsiCodePageData;
/*05C*/ PVOID                InitOemCodePageData;
/*060*/ PVOID                InitUnicodeCaseTableData;
/*064*/ DWORD                NumberOfProcessors;
/*068*/ DWORD                NtGlobalFlag;
/*06C*/ DWORD                dw6C;
/*070*/ LARGE_INTEGER        MmCriticalSectionTimeout;
/*078*/ DWORD                MmHeapSegmentReserve;
/*07C*/ DWORD                MmHeapSegmentCommit;
/*080*/ DWORD                MmHeapDeCommitTotalFreeThreshold;
/*084*/ DWORD                MmHeapDeCommitFreeBlockThreshold;
/*088*/ DWORD                NumberOfHeaps;
/*08C*/ DWORD                MaxNumberOfHeaps; // 902
/*090*/ PHANDLE              ProcessHeapsList;
/*094   PHANDLE_TABLE*/PVOID        GdiSharedHandleTable;
/*098*/ PVOID                ProcessStarterHelper;
/*09C*/ DWORD                GdiDCAttributeList;
/*0A0*/ PCRITICAL_SECTION    LoaderLock;
/*0A4*/ DWORD                NtMajorVersion;
/*0A8*/ DWORD                NtMinorVersion;
/*0AC*/ WORD                 NtBuildNumber;
/*0AE*/ WORD                 CmNtCSDVersion;
/*0B0*/ DWORD                PlatformId;
/*0B4*/ DWORD                Subsystem;
/*0B8*/ DWORD                MajorSubsystemVersion;
/*0BC*/ DWORD                MinorSubsystemVersion;
/*0C0*/ KAFFINITY            AffinityMask;
/*0C4*/ DWORD                GdiHandleBuffer[34];
/*14C*/ PVOID                PostProcessInitRoutine;
/*150*/ PVOID                TlsExpansionBitmap;
/*154*/ UCHAR                TlsExpansionBitmapBits[128];
/*1D4*/ HANDLE               SessionId;
/*1D8*/ DWORD                dw1D8;
/*1DC*/ DWORD                dw1DC;
/*1E0*/ PWORD                CSDVersion;
/*1E4*/ DWORD                dw1E4;
/*1E8*/ } PEB, *PPEB;

typedef struct _KGDTENTRY {
	USHORT LimitLow;
	USHORT BaseLow;
	union {
		struct {
			UCHAR BaseMid;
			UCHAR Flags1;
			UCHAR Flags2;
			UCHAR BaseHi;
		} Bytes;
		struct {
			ULONG BaseMid       : 8;
			ULONG Type          : 5;
			ULONG Dpl           : 2;
			ULONG Pres          : 1;
			ULONG LimitHi       : 4;
			ULONG Sys           : 1;
			ULONG Reserved_0    : 1;
			ULONG DefaultBig    : 1;
			ULONG Granularity   : 1;
			ULONG BaseHi        : 8;
		} Bits;
	} HighWord;

} KGDTENTRY, *PKGDTENTRY;

typedef struct _KIDTENTRY {
	USHORT Offset;
	USHORT Selector;
	USHORT Access;
	USHORT ExtendedOffset;

} KIDTENTRY, *PKIDTENTRY;

typedef struct _KPROCESS {
/*000*/ DISPATCHER_HEADER Header;
/*010*/ LIST_ENTRY        ProfileListHead;
/*018*/ DWORD             DirectoryTableBase;
/*01C*/ DWORD             PageTableBase;
/*020*/ KGDTENTRY         LdtDescriptor;
/*028*/ KIDTENTRY         Int21Descriptor;
/*030*/ WORD              IopmOffset;
/*032*/ BYTE              Iopl;
/*033*/ BOOLEAN           VdmFlag;
/*034*/ DWORD             ActiveProcessors;
/*038*/ DWORD             KernelTime;
/*03C*/ DWORD             UserTime;
/*040*/ LIST_ENTRY        ReadyListHead;
/*048*/ LIST_ENTRY        SwapListEntry;
/*050*/ LIST_ENTRY        ThreadListHead;
/*058*/ PVOID             ProcessLock;
/*05C*/ KAFFINITY         Affinity;
/*060*/ WORD              StackCount;
/*062*/ BYTE              BasePriority;
/*063*/ BYTE              ThreadQuantum;
/*064*/ BOOLEAN           AutoAlignment;
/*065*/ BYTE              State;
/*066*/ BYTE              ThreadSeed;
/*067*/ BOOLEAN           DisableBoost;
/*068*/ BYTE              PowerState;
/*069*/ BYTE              DisableQuantum;
/*06A*/ BYTE              Spare[2];
/*06C*/ } KPROCESS, *PKPROCESS;

typedef struct _KAPC_STATE {
	LIST_ENTRY  ApcListHead[2];
	PKPROCESS   Process;
	BOOLEAN     KernelApcInProgress;
	BOOLEAN     KernelApcPending;
	BOOLEAN     UserApcPending;

} KAPC_STATE, *PKAPC_STATE;

typedef struct _MMSUPPORT {
/*000*/ LARGE_INTEGER LastTrimTime;
/*008*/ DWORD         LastTrimFaultCount;
/*00C*/ DWORD         PageFaultCount;
/*010*/ DWORD         PeakWorkingSetSize;
/*014*/ DWORD         WorkingSetSize;
/*018*/ DWORD         MinimumWorkingSetSize;
/*01C*/ DWORD         MaximumWorkingSetSize;
/*020*/ PVOID         VmWorkingSetList;
/*024*/ LIST_ENTRY    WorkingSetExpansionLinks;
/*02C*/ BOOLEAN       AllowWorkingSetAdjustment;
/*02D*/ BOOLEAN       AddressSpaceBeingDeleted;
/*02E*/ BYTE          ForegroundSwitchCount;
/*02F*/ BYTE          MemoryPriority;

/*030*/ DWORD         SessionSpace    : 1;
/*030*/ DWORD         BeingTrimmed    : 1;
/*030*/ DWORD         ProcessInSession: 1;
/*030*/ DWORD         SessionLeader   : 1;
/*030*/ DWORD         TrimHard        : 1;
/*030*/ DWORD         WorkingSetHard  : 1;
/*030*/ DWORD         WriteWatch      : 1;
/*030*/ DWORD         Filler          : 25;

/*034*/ DWORD         Claim;
/*038*/ DWORD         NextEstimationSlot;
/*03C*/ DWORD         NextAgingSlot;
/*040*/ DWORD         EstimatedAvailable;
/*044*/ DWORD         GrowthSinceLastEstimate;
/*048*/ } MMSUPPORT, *PMMSUPPORT;

#ifdef _X86_
#define HARDWARE_PTE    HARDWARE_PTE_X86
#define PHARDWARE_PTE   PHARDWARE_PTE_X86
#endif // _X86_

typedef struct _HARDWARE_PTE_X86 {
	ULONG Valid             : 1;
	ULONG Write             : 1;
	ULONG Owner             : 1;
	ULONG WriteThrough      : 1;
	ULONG CacheDisable      : 1;
	ULONG Accessed          : 1;
	ULONG Dirty             : 1;
	ULONG LargePage         : 1;
	ULONG Global            : 1;
	ULONG CopyOnWrite       : 1;
	ULONG Prototype         : 1;
	ULONG Reserved          : 1;
	ULONG PageFrameNumber   : 20;

} HARDWARE_PTE_X86, *PHARDWARE_PTE_X86;

typedef struct _QUOTA_BLOCK
{
/*000*/ DWORD Flags;
/*004*/ DWORD ChargeCount;
/*008*/ DWORD PeakPoolUsage [2]; // NonPagedPool, PagedPool
/*010*/ DWORD PoolUsage   [2]; // NonPagedPool, PagedPool
/*018*/ DWORD PoolQuota   [2]; // NonPagedPool, PagedPool
/*020*/ 
} QUOTA_BLOCK, *PQUOTA_BLOCK,	**PPQUOTA_BLOCK;

typedef struct _EPROCESS {
/*000*/ KPROCESS               Pcb;
/*06C*/ NTSTATUS               ExitStatus;
/*070*/ KEVENT                 LockEvent;
/*080*/ DWORD                  LockCount;
/*084*/ DWORD                  d084;
/*088*/ LARGE_INTEGER          CreateTime;
/*090*/ LARGE_INTEGER          ExitTime;
/*098*/ PVOID                  LockOwner;
/*09C*/ DWORD                  UniqueProcessId;
/*0A0*/ LIST_ENTRY             ActiveProcessLinks; // see PsActiveListHead
/*0A8*/ DWORD                  QuotaPeakPoolUsage [2]; // NP, P
/*0B0*/ DWORD                  QuotaPoolUsage     [2]; // NP, P
/*0B8*/ DWORD                  PagefileUsage;
/*0BC*/ DWORD                  CommitCharge;
/*0C0*/ DWORD                  PeakPagefileUsage;
/*0C4*/ DWORD                  PeakVirtualSize;
/*0C8*/ LARGE_INTEGER          VirtualSize;
/*0D0*/ MMSUPPORT              Vm;
/*118*/ LIST_ENTRY             SessionProcessLinks;
/*120*/ PVOID                  DebugPort;
/*124*/ PVOID                  ExceptionPort;
/*128 PHANDLE_TABLE*/PVOID          ObjectTable;
/*12C*/ PVOID                  Token;
/*130*/ FAST_MUTEX             WorkingSetLock;
/*150*/ DWORD                  WorkingSetPage;
/*154*/ BOOLEAN                ProcessOutswapEnabled;
/*155*/ BOOLEAN                ProcessOutswapped;
/*156*/ BOOLEAN                AddressSpaceInitialized;
/*157*/ BOOLEAN                AddressSpaceDeleted;
/*158*/ FAST_MUTEX             AddressCreationLock;
/*178*/ KSPIN_LOCK             HyperSpaceLock;
/*17C*/ DWORD                  ForkInProgress;
/*180*/ WORD                   VmOperation;
/*182*/ BOOLEAN                ForkWasSuccessful;
/*183*/ BYTE                   MmAgressiveWsTrimMask;
/*184*/ DWORD                  VmOperationEvent;
/*188*/ HARDWARE_PTE           PageDirectoryPte;
/*18C*/ DWORD                  LastFaultCount;
/*190*/ DWORD                  ModifiedPageCount;
/*194*/ PVOID                  VadRoot;
/*198*/ PVOID                  VadHint;
/*19C*/ PVOID                  CloneRoot;
/*1A0*/ DWORD                  NumberOfPrivatePages;
/*1A4*/ DWORD                  NumberOfLockedPages;
/*1A8*/ WORD                   NextPageColor;
/*1AA*/ BOOLEAN                ExitProcessCalled;
/*1AB*/ BOOLEAN                CreateProcessReported;
/*1AC*/ HANDLE                 SectionHandle;
/*1B0*/ struct _PEB           *Peb;
/*1B4*/ PVOID                  SectionBaseAddress;
/*1B8*/ PQUOTA_BLOCK           QuotaBlock;
/*1BC*/ NTSTATUS               LastThreadExitStatus;
/*1C0*/ DWORD                  WorkingSetWatch;
/*1C4*/ HANDLE                 Win32WindowStation;
/*1C8*/ DWORD                  InheritedFromUniqueProcessId;
/*1CC*/ ACCESS_MASK            GrantedAccess;
/*1D0*/ DWORD                  DefaultHardErrorProcessing; // HEM_*
/*1D4*/ DWORD                  LdtInformation;
/*1D8*/ PVOID                  VadFreeHint;
/*1DC*/ DWORD                  VdmObjects;
/*1E0*/ PVOID                  DeviceMap;
/*1E4*/ DWORD                  SessionId;
/*1E8*/ LIST_ENTRY             PhysicalVadList;
/*1F0*/ HARDWARE_PTE           PageDirectoryPte2;
/*1F8*/ DWORD                  PaePageDirectoryPage;
/*1FC*/ CHAR                   ImageFileName[16];
/*20C*/ DWORD                  VmTrimFaultValue;
/*210*/ BYTE                   SetTimerResolution;
/*211*/ BYTE                   PriorityClass;
/*212*/ WORD                   SubSystemVersion;
/*214 struct _WIN32_PROCESS * */ PVOID Win32Process;
/*218*/ PVOID                  Job;
/*21C*/ DWORD                  JobStatus;
/*220*/ LIST_ENTRY             JobLinks;
/*228*/ PVOID                  LockedPagesList;
/*22C*/ PVOID                  SecurityPort;
/*230*/ PVOID                  Wow64;
/*234*/ DWORD                  d234;
/*238*/ IO_COUNTERS            IoCounters;
/*268*/ DWORD                  CommitChargeLimit;
/*26C*/ DWORD                  CommitChargePeak;
/*270*/ LIST_ENTRY             ThreadListHead;
/*278*/ PRTL_BITMAP            VadPhysicalPagesBitMap;
/*27C*/ DWORD                  VadPhysicalPages;
/*280*/ DWORD                  AweLock;
/*284*/ } EPROCESS, *PEPROCESS;

typedef struct _TIB
{
	PVOID pvExcept;						// 00h Head of exception record list
	PVOID   pvStackUserTop;   // 04h Top of user stack
	PVOID   pvStackUserBase;  // 08h Base of user stack
	PVOID SubSystemTib;				// 0Ch
	ULONG FiberData;					// 10h
	PVOID   pvArbitrary;      // 14h Available for application use
	struct _TIB *ptibSelf;    // 18h Linear address of TIB structure
	ULONG unknown1;           // 1Ch
	ULONG processID;          // 20h
	ULONG threadID;           // 24h
	ULONG unknown2;           // 28h
	PVOID*  pvTLSArray;       // 2Ch Thread Local Storage array
	struct _PEB *pPEB;				// 30h Pointer to owning process database
} TIB, *PTIB;

#pragma pack()

#endif
