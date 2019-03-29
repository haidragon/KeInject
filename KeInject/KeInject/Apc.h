#pragma once

#include <ntifs.h>
#include "PEStruct.h"
#include "NtFunction.h"


NTSTATUS ApcQueueExecution(
	 PEPROCESS pEProcess,
	 BOOLEAN IsWow64,
	 PVOID Code,
	 PVOID Param
);

//Win7 x64
//kd > dt _teb
//ntdll!_TEB
//+ 0x000 NtTib            : _NT_TIB
//+ 0x038 EnvironmentPointer : Ptr64 Void
//+ 0x040 ClientId : _CLIENT_ID
//+ 0x050 ActiveRpcHandle : Ptr64 Void
//+ 0x058 ThreadLocalStoragePointer : Ptr64 Void
//+ 0x060 ProcessEnvironmentBlock : Ptr64 _PEB
//+ 0x068 LastErrorValue : Uint4B
//+ 0x06c CountOfOwnedCriticalSections : Uint4B
//+ 0x070 CsrClientThread : Ptr64 Void
//+ 0x078 Win32ThreadInfo : Ptr64 Void
//+ 0x080 User32Reserved : [26] Uint4B
//+ 0x0e8 UserReserved : [5] Uint4B
//+ 0x100 WOW32Reserved : Ptr64 Void
//+ 0x108 CurrentLocale : Uint4B
//+ 0x10c FpSoftwareStatusRegister : Uint4B
//+ 0x110 SystemReserved1 : [54] Ptr64 Void
//+ 0x2c0 ExceptionCode : Int4B
//+ 0x2c8 ActivationContextStackPointer : Ptr64 _ACTIVATION_CONTEXT_STACK
//+ 0x2d0 SpareBytes : [24] UChar
//+ 0x2e8 TxFsContext : Uint4B
//+ 0x2f0 GdiTebBatch : _GDI_TEB_BATCH
//+ 0x7d8 RealClientId : _CLIENT_ID
//+ 0x7e8 GdiCachedProcessHandle : Ptr64 Void
//+ 0x7f0 GdiClientPID : Uint4B
//+ 0x7f4 GdiClientTID : Uint4B
//+ 0x7f8 GdiThreadLocalInfo : Ptr64 Void
//+ 0x800 Win32ClientInfo : [62] Uint8B
//+ 0x9f0 glDispatchTable : [233] Ptr64 Void
//+ 0x1138 glReserved1 : [29] Uint8B
//+ 0x1220 glReserved2 : Ptr64 Void
//+ 0x1228 glSectionInfo : Ptr64 Void
//+ 0x1230 glSection : Ptr64 Void
//+ 0x1238 glTable : Ptr64 Void
//+ 0x1240 glCurrentRC : Ptr64 Void
//+ 0x1248 glContext : Ptr64 Void
//+ 0x1250 LastStatusValue : Uint4B
//+ 0x1258 StaticUnicodeString : _UNICODE_STRING
//+ 0x1268 StaticUnicodeBuffer : [261] Wchar
//+ 0x1478 DeallocationStack : Ptr64 Void
//+ 0x1480 TlsSlots : [64] Ptr64 Void
//+ 0x1680 TlsLinks : _LIST_ENTRY
//+ 0x1690 Vdm : Ptr64 Void
//+ 0x1698 ReservedForNtRpc : Ptr64 Void
//+ 0x16a0 DbgSsReserved : [2] Ptr64 Void
//+ 0x16b0 HardErrorMode : Uint4B
//+ 0x16b8 Instrumentation : [11] Ptr64 Void
//+ 0x1710 ActivityId : _GUID
//+ 0x1720 SubProcessTag : Ptr64 Void
//+ 0x1728 EtwLocalData : Ptr64 Void
//+ 0x1730 EtwTraceData : Ptr64 Void
//+ 0x1738 WinSockData : Ptr64 Void
//+ 0x1740 GdiBatchCount : Uint4B
//+ 0x1744 CurrentIdealProcessor : _PROCESSOR_NUMBER
//+ 0x1744 IdealProcessorValue : Uint4B
//+ 0x1744 ReservedPad0 : UChar
//+ 0x1745 ReservedPad1 : UChar
//+ 0x1746 ReservedPad2 : UChar
//+ 0x1747 IdealProcessor : UChar
//+ 0x1748 GuaranteedStackBytes : Uint4B
//+ 0x1750 ReservedForPerf : Ptr64 Void
//+ 0x1758 ReservedForOle : Ptr64 Void
//+ 0x1760 WaitingOnLoaderLock : Uint4B
//+ 0x1768 SavedPriorityState : Ptr64 Void
//+ 0x1770 SoftPatchPtr1 : Uint8B
//+ 0x1778 ThreadPoolData : Ptr64 Void
//+ 0x1780 TlsExpansionSlots : Ptr64 Ptr64 Void
//+ 0x1788 DeallocationBStore : Ptr64 Void
//+ 0x1790 BStoreLimit : Ptr64 Void
//+ 0x1798 MuiGeneration : Uint4B
//+ 0x179c IsImpersonating : Uint4B
//+ 0x17a0 NlsCache : Ptr64 Void
//+ 0x17a8 pShimData : Ptr64 Void
//+ 0x17b0 HeapVirtualAffinity : Uint4B
//+ 0x17b8 CurrentTransactionHandle : Ptr64 Void
//+ 0x17c0 ActiveFrame : Ptr64 _TEB_ACTIVE_FRAME
//+ 0x17c8 FlsData : Ptr64 Void
//+ 0x17d0 PreferredLanguages : Ptr64 Void
//+ 0x17d8 UserPrefLanguages : Ptr64 Void
//+ 0x17e0 MergedPrefLanguages : Ptr64 Void
//+ 0x17e8 MuiImpersonation : Uint4B
//+ 0x17ec CrossTebFlags : Uint2B
//+ 0x17ec SpareCrossTebBits : Pos 0, 16 Bits
//+ 0x17ee SameTebFlags : Uint2B
//+ 0x17ee SafeThunkCall : Pos 0, 1 Bit
//+ 0x17ee InDebugPrint : Pos 1, 1 Bit
//+ 0x17ee HasFiberData : Pos 2, 1 Bit
//+ 0x17ee SkipThreadAttach : Pos 3, 1 Bit
//+ 0x17ee WerInShipAssertCode : Pos 4, 1 Bit
//+ 0x17ee RanProcessInit : Pos 5, 1 Bit
//+ 0x17ee ClonedThread : Pos 6, 1 Bit
//+ 0x17ee SuppressDebugMsg : Pos 7, 1 Bit
//+ 0x17ee DisableUserStackWalk : Pos 8, 1 Bit
//+ 0x17ee RtlExceptionAttached : Pos 9, 1 Bit
//+ 0x17ee InitialThread : Pos 10, 1 Bit
//+ 0x17ee SpareSameTebBits : Pos 11, 5 Bits
//+ 0x17f0 TxnScopeEnterCallback : Ptr64 Void
//+ 0x17f8 TxnScopeExitCallback : Ptr64 Void
//+ 0x1800 TxnScopeContext : Ptr64 Void
//+ 0x1808 LockCount : Uint4B
//+ 0x180c SpareUlong0 : Uint4B
//+ 0x1810 ResourceRetValue : Ptr64 Void

typedef void * POINTER_32 PVOID32;
typedef struct _ACTIVATION_CONTEXT_STACK_T
{
	PVOID /*struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME**/ ActiveFrame;
	LIST_ENTRY FrameListCache;
	UINT32 Flags;
	UINT32 NextCookieSequenceNumber;
	UINT32 StackId;
}ACTIVATION_CONTEXT_STACK,*PACTIVATION_CONTEXT_STACK; /* size: 0x0028 */ /* size: 0x0018 */

typedef struct _ACTIVATION_CONTEXT_STACK32
{
	PVOID32 /*struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME**/ ActiveFrame;
	LIST_ENTRY32 FrameListCache;
	UINT32 Flags;
	UINT32 NextCookieSequenceNumber;
	UINT32 StackId;
}ACTIVATION_CONTEXT_STACK32, *PACTIVATION_CONTEXT_STACK32; /* size: 0x0028 */ /* size: 0x0018 */

typedef struct _ACTIVATION_CONTEXT_STACK64
{
	PVOID64 /*struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME**/ ActiveFrame;
	LIST_ENTRY64 FrameListCache;
	UINT32 Flags;
	UINT32 NextCookieSequenceNumber;
	UINT32 StackId;
}ACTIVATION_CONTEXT_STACK64, *PACTIVATION_CONTEXT_STACK64; /* size: 0x0028 */ /* size: 0x0018 */


typedef struct _GDI_TEB_BATCH_T
{
	struct /* bitfield */
	{
		UINT32 Offset : 31; /* bit position: 0 */
		UINT32 HasRenderingCommand : 1; /* bit position: 31 */
	}; /* bitfield */
	SIZE_T HDC;
	UINT32 Buffer[310];
}GDI_TEB_BATCH,*PGDI_TEB_BATCH; /* size: 0x04e8 */ /* size: 0x04e0 */

typedef struct _GDI_TEB_BATCH32
{
	struct /* bitfield */
	{
		UINT32 Offset : 31; /* bit position: 0 */
		UINT32 HasRenderingCommand : 1; /* bit position: 31 */
	}; /* bitfield */
	UINT32 HDC;
	UINT32 Buffer[310];
}GDI_TEB_BATCH32, *PGDI_TEB_BATCH32; /* size: 0x04e8 */ /* size: 0x04e0 */

typedef struct _GDI_TEB_BATCH64
{
	struct /* bitfield */
	{
		UINT32 Offset : 31; /* bit position: 0 */
		UINT32 HasRenderingCommand : 1; /* bit position: 31 */
	}; /* bitfield */
	UINT64 HDC;
	UINT32 Buffer[310];
}GDI_TEB_BATCH64, *PGDI_TEB_BATCH64; /* size: 0x04e8 */ /* size: 0x04e0 */



typedef struct _TEB
{
	//enum STLEN
	//{
	//	StaticUnicodeBufferSize = 260 + 1, // MAX_PATH + 1

	//	SystemReserveed1SizeX86 = 26,
	//	SystemReserveed1SizeX64 = 30,
	//	SystemReserveed1Size = sizeof(SIZE_T) == sizeof(UINT64) ? SystemReserveed1SizeX64 : SystemReserveed1SizeX86,

	//	InstrumentationX86 = 9,
	//	InstrumentationX64 = 11,
	//	InstrumentationCount = sizeof(SIZE_T) == sizeof(UINT64) ? InstrumentationX64 : InstrumentationX86,
	//};

	struct _NT_TIB NtTib;
	VOID* EnvironmentPointer;
	struct _CLIENT_ID ClientId;
	VOID* ActiveRpcHandle;
	VOID* ThreadLocalStoragePointer;
	struct _PEB* ProcessEnvironmentBlock;
	UINT32 LastErrorValue;
	UINT32 CountOfOwnedCriticalSections;
	VOID* CsrClientThread;
	VOID* Win32ThreadInfo;
	UINT32 User32Reserved[26];
	UINT32 UserReserved[5];
	VOID* WOW32Reserved;
	UINT32 CurrentLocale;
	UINT32 FpSoftwareStatusRegister;
	VOID* ReservedForDebuggerInstrumentation[16];
	VOID* SystemReserved1[30];
	CHAR PlaceholderCompatibilityMode;
	UINT8 PlaceholderHydrationAlwaysExplicit;
	CHAR PlaceholderReserved[10];
	UINT32 ProxiedProcessId;
	ACTIVATION_CONTEXT_STACK _ActivationStack;
	UINT8 WorkingOnBehalfTicket[8];
	INT32 ExceptionCode;
	PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
	SIZE_T InstrumentationCallbackSp;
	SIZE_T InstrumentationCallbackPreviousPc;
	SIZE_T InstrumentationCallbackPreviousSp;
#ifdef _WIN64
	UINT32 TxFsContext;
#endif
	UINT8 InstrumentationCallbackDisabled;
#ifdef _WIN64
	UINT8 UnalignedLoadStoreExceptions;
#else
	UINT8 SpareBytes[23];
	UINT32 TxFsContext;
#endif
	GDI_TEB_BATCH GdiTebBatch;
	struct _CLIENT_ID RealClientId;
	VOID* GdiCachedProcessHandle;
	UINT32 GdiClientPID;
	UINT32 GdiClientTID;
	VOID* GdiThreadLocalInfo;
	SIZE_T Win32ClientInfo[62];
	VOID* glDispatchTable[233];
	SIZE_T glReserved1[29];
	VOID* glReserved2;
	VOID* glSectionInfo;
	VOID* glSection;
	VOID* glTable;
	VOID* glCurrentRC;
	VOID* glContext;
	UINT32 LastStatusValue;
	struct _UNICODE_STRING StaticUnicodeString;
	WCHAR StaticUnicodeBuffer[261];
	VOID* DeallocationStack;
	VOID* TlsSlots[64];
	struct _LIST_ENTRY TlsLinks;
	VOID* Vdm;
	VOID* ReservedForNtRpc;
	VOID* DbgSsReserved[2];
	UINT32 HardErrorMode;
	VOID* Instrumentation[11];
	struct _GUID ActivityId;
	VOID* SubProcessTag;
	VOID* PerflibData;
	VOID* EtwTraceData;
	VOID* WinSockData;
	UINT32 GdiBatchCount;
	union
	{
		struct _PROCESSOR_NUMBER CurrentIdealProcessor;
		UINT32 IdealProcessorValue;
		struct
		{
			UINT8 ReservedPad0;
			UINT8 ReservedPad1;
			UINT8 ReservedPad2;
			UINT8 IdealProcessor;
		}; /* size: 0x0004 */
	}; /* size: 0x0004 */
	UINT32 GuaranteedStackBytes;
	VOID* ReservedForPerf;
	VOID* ReservedForOle;
	UINT32 WaitingOnLoaderLock;
	VOID* SavedPriorityState;
	SIZE_T ReservedForCodeCoverage;
	VOID* ThreadPoolData;
	VOID** TlsExpansionSlots;
#ifdef _WIN64
	VOID* DeallocationBStore;
	VOID* BStoreLimit;
#endif
	UINT32 MuiGeneration;
	UINT32 IsImpersonating;
	VOID* NlsCache;
	VOID* pShimData;
	UINT32 HeapData;
	VOID* CurrentTransactionHandle;
	PVOID ActiveFrame;
	VOID* FlsData;
	VOID* PreferredLanguages;
	VOID* UserPrefLanguages;
	VOID* MergedPrefLanguages;
	UINT32 MuiImpersonation;
	union
	{
		volatile UINT16 CrossTebFlags;
		UINT16 SpareCrossTebBits : 16; /* bit position: 0 */
	}; /* size: 0x0002 */
	union
	{
		UINT16 SameTebFlags;
		struct /* bitfield */
		{
			UINT16 SafeThunkCall : 1; /* bit position: 0 */
			UINT16 InDebugPrint : 1; /* bit position: 1 */
			UINT16 HasFiberData : 1; /* bit position: 2 */
			UINT16 SkipThreadAttach : 1; /* bit position: 3 */
			UINT16 WerInShipAssertCode : 1; /* bit position: 4 */
			UINT16 RanProcessInit : 1; /* bit position: 5 */
			UINT16 ClonedThread : 1; /* bit position: 6 */
			UINT16 SuppressDebugMsg : 1; /* bit position: 7 */
			UINT16 DisableUserStackWalk : 1; /* bit position: 8 */
			UINT16 RtlExceptionAttached : 1; /* bit position: 9 */
			UINT16 InitialThread : 1; /* bit position: 10 */
			UINT16 SessionAware : 1; /* bit position: 11 */
			UINT16 LoadOwner : 1; /* bit position: 12 */
			UINT16 LoaderWorker : 1; /* bit position: 13 */
			UINT16 SkipLoaderInit : 1; /* bit position: 14 */
			UINT16 SpareSameTebBits : 1; /* bit position: 15 */
		}; /* bitfield */
	}; /* size: 0x0002 */
	VOID* TxnScopeEnterCallback;
	VOID* TxnScopeExitCallback;
	VOID* TxnScopeContext;
	UINT32 LockCount;
	INT32 WowTebOffset;
} TEB, *PTEB; /* size: 0x1810 */ /* size: 0x0fe0 */


typedef struct _TEB32
{
	//enum  UINT32
	//{
	//	StaticUnicodeBufferSize = 260 + 1, // MAX_PATH + 1

	//	SystemReserveed1SizeX86 = 26,
	//	SystemReserveed1SizeX64 = 30,
	//	SystemReserveed1Size = sizeof(SIZE_T) == sizeof(UINT64) ? SystemReserveed1SizeX64 : SystemReserveed1SizeX86,

	//	InstrumentationX86 = 9,
	//	InstrumentationX64 = 11,
	//	InstrumentationCount = sizeof(SIZE_T) == sizeof(UINT64) ? InstrumentationX64 : InstrumentationX86,
	//};
	struct _NT_TIB32 NtTib;
	PVOID32 EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID32 ActiveRpcHandle;
	PVOID32 ThreadLocalStoragePointer;
	PVOID32 /*struct _PEB32**/ ProcessEnvironmentBlock;
	UINT32 LastErrorValue;
	UINT32 CountOfOwnedCriticalSections;
	PVOID32 CsrClientThread;
	PVOID32 Win32ThreadInfo;
	UINT32 User32Reserved[26];
	UINT32 UserReserved[5];
	PVOID32 WOW32Reserved;
	UINT32 CurrentLocale;
	UINT32 FpSoftwareStatusRegister;
	PVOID32 ReservedForDebuggerInstrumentation[16];
	PVOID32 SystemReserved1[26];
	CHAR PlaceholderCompatibilityMode;
	UINT8 PlaceholderHydrationAlwaysExplicit;
	CHAR PlaceholderReserved[10];
	UINT32 ProxiedProcessId;
	ACTIVATION_CONTEXT_STACK32 _ActivationStack;
	UINT8 WorkingOnBehalfTicket[8];
	INT32 ExceptionCode;
	PVOID32 /*struct _ACTIVATION_CONTEXT_STACK32**/ ActivationContextStackPointer;
	UINT32 InstrumentationCallbackSp;
	UINT32 InstrumentationCallbackPreviousPc;
	UINT32 InstrumentationCallbackPreviousSp;
	UINT8 InstrumentationCallbackDisabled;
	UINT8 SpareBytes[23];
	UINT32 TxFsContext;
	GDI_TEB_BATCH32 GdiTebBatch;
	CLIENT_ID RealClientId;
	PVOID32 GdiCachedProcessHandle;
	UINT32 GdiClientPID;
	UINT32 GdiClientTID;
	PVOID32 GdiThreadLocalInfo;
	UINT32 Win32ClientInfo[62];
	PVOID32 glDispatchTable[233];
	UINT32 glReserved1[29];
	PVOID32 glReserved2;
	PVOID32 glSectionInfo;
	PVOID32 glSection;
	PVOID32 glTable;
	PVOID32 glCurrentRC;
	PVOID32 glContext;
	UINT32 LastStatusValue;
	UNICODE_STRING32 StaticUnicodeString;
	WCHAR StaticUnicodeBuffer[261];
	PVOID32 DeallocationStack;
	PVOID32 TlsSlots[64];
	LIST_ENTRY32 TlsLinks;
	PVOID32 Vdm;
	PVOID32 ReservedForNtRpc;
	PVOID32 DbgSsReserved[2];
	UINT32 HardErrorMode;
	PVOID32 Instrumentation[9];
	struct _GUID ActivityId;
	PVOID32 SubProcessTag;
	PVOID32 PerflibData;
	PVOID32 EtwTraceData;
	PVOID32 WinSockData;
	UINT32 GdiBatchCount;
	union
	{
		struct _PROCESSOR_NUMBER CurrentIdealProcessor;
		UINT32 IdealProcessorValue;
		struct
		{
			UINT8 ReservedPad0;
			UINT8 ReservedPad1;
			UINT8 ReservedPad2;
			UINT8 IdealProcessor;
		}; /* size: 0x0004 */
	}; /* size: 0x0004 */
	UINT32 GuaranteedStackBytes;
	PVOID32 ReservedForPerf;
	PVOID32 ReservedForOle;
	UINT32 WaitingOnLoaderLock;
	PVOID32 SavedPriorityState;
	UINT32 ReservedForCodeCoverage;
	PVOID32 ThreadPoolData;
	PVOID32 /*VOID***/ TlsExpansionSlots;
	UINT32 MuiGeneration;
	UINT32 IsImpersonating;
	PVOID32 NlsCache;
	PVOID32 pShimData;
	UINT32 HeapData;
	PVOID32 CurrentTransactionHandle;
	PVOID32 /*struct _TEB_ACTIVE_FRAME**/ ActiveFrame;
	PVOID32 FlsData;
	PVOID32 PreferredLanguages;
	PVOID32 UserPrefLanguages;
	PVOID32 MergedPrefLanguages;
	UINT32 MuiImpersonation;
	union
	{
		volatile UINT16 CrossTebFlags;
		UINT16 SpareCrossTebBits : 16; /* bit position: 0 */
	}; /* size: 0x0002 */
	union
	{
		UINT16 SameTebFlags;
		struct /* bitfield */
		{
			UINT16 SafeThunkCall : 1; /* bit position: 0 */
			UINT16 InDebugPrint : 1; /* bit position: 1 */
			UINT16 HasFiberData : 1; /* bit position: 2 */
			UINT16 SkipThreadAttach : 1; /* bit position: 3 */
			UINT16 WerInShipAssertCode : 1; /* bit position: 4 */
			UINT16 RanProcessInit : 1; /* bit position: 5 */
			UINT16 ClonedThread : 1; /* bit position: 6 */
			UINT16 SuppressDebugMsg : 1; /* bit position: 7 */
			UINT16 DisableUserStackWalk : 1; /* bit position: 8 */
			UINT16 RtlExceptionAttached : 1; /* bit position: 9 */
			UINT16 InitialThread : 1; /* bit position: 10 */
			UINT16 SessionAware : 1; /* bit position: 11 */
			UINT16 LoadOwner : 1; /* bit position: 12 */
			UINT16 LoaderWorker : 1; /* bit position: 13 */
			UINT16 SkipLoaderInit : 1; /* bit position: 14 */
			UINT16 SpareSameTebBits : 1; /* bit position: 15 */
		}; /* bitfield */
	}; /* size: 0x0002 */
	PVOID32 TxnScopeEnterCallback;
	PVOID32 TxnScopeExitCallback;
	PVOID32 TxnScopeContext;
	UINT32 LockCount;
	INT32 WowTebOffset;
} TEB32, *PTEB32; /* size: 0x1810 */ /* size: 0x0fe0 */



typedef struct _TEB64
{
	//enum  UINT32
	//{
	//	StaticUnicodeBufferSize = 260 + 1, // MAX_PATH + 1

	//	SystemReserveed1SizeX86 = 26,
	//	SystemReserveed1SizeX64 = 30,
	//	SystemReserveed1Size = sizeof(SIZE_T) == sizeof(UINT64) ? SystemReserveed1SizeX64 : SystemReserveed1SizeX86,

	//	InstrumentationX86 = 9,
	//	InstrumentationX64 = 11,
	//	InstrumentationCount = sizeof(SIZE_T) == sizeof(UINT64) ? InstrumentationX64 : InstrumentationX86,
	//};

	struct _NT_TIB64 NtTib;
	PVOID64 EnvironmentPointer;
	CLIENT_ID ClientId;
	PVOID64 ActiveRpcHandle;
	PVOID64 ThreadLocalStoragePointer;
	PVOID64 /*struct _PEB64**/ ProcessEnvironmentBlock;
	UINT32 LastErrorValue;
	UINT32 CountOfOwnedCriticalSections;
	PVOID64 CsrClientThread;
	PVOID64 Win32ThreadInfo;
	UINT32 User32Reserved[26];
	UINT32 UserReserved[5];
	PVOID64 WOW32Reserved;
	UINT32 CurrentLocale;
	UINT32 FpSoftwareStatusRegister;
	PVOID64 ReservedForDebuggerInstrumentation[16];
	PVOID64 SystemReserved1[30];
	CHAR PlaceholderCompatibilityMode;
	UINT8 PlaceholderHydrationAlwaysExplicit;
	CHAR PlaceholderReserved[10];
	UINT32 ProxiedProcessId;
	ACTIVATION_CONTEXT_STACK64 _ActivationStack;
	UINT8 WorkingOnBehalfTicket[8];
	INT32 ExceptionCode;
	PVOID64 /*struct _ACTIVATION_CONTEXT_STACK64**/ ActivationContextStackPointer;
	UINT64 InstrumentationCallbackSp;
	UINT64 InstrumentationCallbackPreviousPc;
	UINT64 InstrumentationCallbackPreviousSp;
	UINT32 TxFsContext;
	UINT8 InstrumentationCallbackDisabled;
	UINT8 UnalignedLoadStoreExceptions;
	GDI_TEB_BATCH64 GdiTebBatch;
	CLIENT_ID RealClientId;
	PVOID64 GdiCachedProcessHandle;
	UINT32 GdiClientPID;
	UINT32 GdiClientTID;
	PVOID64 GdiThreadLocalInfo;
	UINT64 Win32ClientInfo[62];
	PVOID64 glDispatchTable[233];
	UINT64 glReserved1[29];
	PVOID64 glReserved2;
	PVOID64 glSectionInfo;
	PVOID64 glSection;
	PVOID64 glTable;
	PVOID64 glCurrentRC;
	PVOID64 glContext;
	UINT32 LastStatusValue;
	UNICODE_STRING64 StaticUnicodeString;
	WCHAR StaticUnicodeBuffer[261];
	PVOID64 DeallocationStack;
	PVOID64 TlsSlots[64];
	LIST_ENTRY64 TlsLinks;
	PVOID64 Vdm;
	PVOID64 ReservedForNtRpc;
	PVOID64 DbgSsReserved[2];
	UINT32 HardErrorMode;
	PVOID64 Instrumentation[11];
	struct _GUID ActivityId;
	PVOID64 SubProcessTag;
	PVOID64 PerflibData;
	PVOID64 EtwTraceData;
	PVOID64 WinSockData;
	UINT32 GdiBatchCount;
	union
	{
		struct _PROCESSOR_NUMBER CurrentIdealProcessor;
		UINT32 IdealProcessorValue;
		struct
		{
			UINT8 ReservedPad0;
			UINT8 ReservedPad1;
			UINT8 ReservedPad2;
			UINT8 IdealProcessor;
		}; /* size: 0x0004 */
	}; /* size: 0x0004 */
	UINT32 GuaranteedStackBytes;
	PVOID64 ReservedForPerf;
	PVOID64 ReservedForOle;
	UINT32 WaitingOnLoaderLock;
	PVOID64 SavedPriorityState;
	UINT64 ReservedForCodeCoverage;
	PVOID64 ThreadPoolData;
	PVOID64 /*VOID***/ TlsExpansionSlots;
	PVOID64 DeallocationBStore;
	PVOID64 BStoreLimit;
	UINT32 MuiGeneration;
	UINT32 IsImpersonating;
	PVOID64 NlsCache;
	PVOID64 pShimData;
	UINT32 HeapData;
	PVOID64 CurrentTransactionHandle;
	PVOID64 /*struct _TEB_ACTIVE_FRAME**/ ActiveFrame;
	PVOID64 FlsData;
	PVOID64 PreferredLanguages;
	PVOID64 UserPrefLanguages;
	PVOID64 MergedPrefLanguages;
	UINT32 MuiImpersonation;
	union
	{
		volatile UINT16 CrossTebFlags;
		UINT16 SpareCrossTebBits : 16; /* bit position: 0 */
	}; /* size: 0x0002 */
	union
	{
		UINT16 SameTebFlags;
		struct /* bitfield */
		{
			UINT16 SafeThunkCall : 1; /* bit position: 0 */
			UINT16 InDebugPrint : 1; /* bit position: 1 */
			UINT16 HasFiberData : 1; /* bit position: 2 */
			UINT16 SkipThreadAttach : 1; /* bit position: 3 */
			UINT16 WerInShipAssertCode : 1; /* bit position: 4 */
			UINT16 RanProcessInit : 1; /* bit position: 5 */
			UINT16 ClonedThread : 1; /* bit position: 6 */
			UINT16 SuppressDebugMsg : 1; /* bit position: 7 */
			UINT16 DisableUserStackWalk : 1; /* bit position: 8 */
			UINT16 RtlExceptionAttached : 1; /* bit position: 9 */
			UINT16 InitialThread : 1; /* bit position: 10 */
			UINT16 SessionAware : 1; /* bit position: 11 */
			UINT16 LoadOwner : 1; /* bit position: 12 */
			UINT16 LoaderWorker : 1; /* bit position: 13 */
			UINT16 SkipLoaderInit : 1; /* bit position: 14 */
			UINT16 SpareSameTebBits : 1; /* bit position: 15 */
		}; /* bitfield */
	}; /* size: 0x0002 */
	PVOID64 TxnScopeEnterCallback;
	PVOID64 TxnScopeExitCallback;
	PVOID64 TxnScopeContext;
	UINT32 LockCount;
	INT32 WowTebOffset;
} TEB64, *PTEB64; /* size: 0x1810 */ /* size: 0x0fe0 */