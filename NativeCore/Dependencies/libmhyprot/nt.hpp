/*
 * MIT License
 *
 * Copyright (c) 2020 Kento Oki
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#pragma once
#include <Windows.h>

//
// windows native definitions
//

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL              ((NTSTATUS)0xC0000001L)
#define STATUS_NOT_IMPLEMENTED           ((NTSTATUS)0xC0000002L)
#define STATUS_INFO_LENGTH_MISMATCH      ((NTSTATUS)0xC0000004L)
#define STATUS_INVALID_CID               ((NTSTATUS)0xC000000BL)
#define STATUS_NO_SUCH_DEVICE            ((NTSTATUS)0xC000000EL)
#define STATUS_NO_SUCH_FILE              ((NTSTATUS)0xC000000FL)
#define STATUS_INVALID_DEVICE_REQUEST    ((NTSTATUS)0xC0000010L)
#define STATUS_MORE_PROCESSING_REQUIRED  ((NTSTATUS)0xC0000016L)
#define STATUS_CONFLICTING_ADDRESSES     ((NTSTATUS)0xC0000018L)
#define STATUS_NO_MORE_ENTRIES           ((NTSTATUS)0x8000001AL)
#define STATUS_BUFFER_TOO_SMALL          ((NTSTATUS)0xC0000023L)
#define STATUS_INVALID_PAGE_PROTECTION   ((NTSTATUS)0xC0000045L)
#define STATUS_PROCEDURE_NOT_FOUND       ((NTSTATUS)0xC000007AL)
#define STATUS_INSUFFICIENT_RESOURCES    ((NTSTATUS)0xC000009AL)
#define STATUS_INSTRUCTION_MISALIGNMENT  ((NTSTATUS)0xC00000AAL)
#define STATUS_INTERNAL_ERROR            ((NTSTATUS)0xC00000E5L)
#define STATUS_INVALID_PARAMETER_1       ((NTSTATUS)0xC00000EFL)
#define STATUS_INVALID_PARAMETER_2       ((NTSTATUS)0xC00000F0L)
#define STATUS_INVALID_PARAMETER_3       ((NTSTATUS)0xC00000F1L)
#define STATUS_INVALID_PARAMETER_4       ((NTSTATUS)0xC00000F2L)
#define STATUS_INVALID_PARAMETER_5       ((NTSTATUS)0xC00000F3L)
#define STATUS_INVALID_PARAMETER_6       ((NTSTATUS)0xC00000F4L)
#define STATUS_INVALID_PARAMETER_7       ((NTSTATUS)0xC00000F5L)
#define STATUS_INVALID_PARAMETER_8       ((NTSTATUS)0xC00000F6L)
#define STATUS_INVALID_PARAMETER_9       ((NTSTATUS)0xC00000F7L)
#define STATUS_INVALID_PARAMETER_10      ((NTSTATUS)0xC00000F8L)
#define STATUS_INVALID_PARAMETER_11      ((NTSTATUS)0xC00000F9L)
#define STATUS_INVALID_PARAMETER_12      ((NTSTATUS)0xC00000FAL)
#define STATUS_INVALID_ADDRESS           ((NTSTATUS)0xC0000141L)
#define STATUS_DATATYPE_MISALIGNMENT_ERROR ((NTSTATUS)0xC00002C5L)

typedef LONG KPRIORITY;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation                  = 0,
    SystemProcessorInformation              = 1,
    SystemPerformanceInformation            = 2,
    SystemTimeOfDayInformation              = 3,
    SystemPathInformation                   = 4,
    SystemProcessInformation                = 5,
    SystemCallCountInformation              = 6,
    SystemDeviceInformation                 = 7,
    SystemProcessorPerformanceInformation   = 8,
    SystemFlagsInformation                  = 9,
    SystemCallTimeInformation               = 10,
    SystemModuleInformation                 = 11,
    SystemLocksInformation                  = 12,
    SystemStackTraceInformation             = 13,
    SystemPagedPoolInformation              = 14,
    SystemNonPagedPoolInformation           = 15,
    SystemHandleInformation                 = 16,
    SystemObjectInformation                 = 17,
    SystemPageFileInformation               = 18,
    SystemVdmInstemulInformation            = 19,
    SystemVdmBopInformation                 = 20,
    SystemFileCacheInformation              = 21,
    SystemPoolTagInformation                = 22,
    SystemInterruptInformation              = 23,
    SystemDpcBehaviorInformation            = 24,
    SystemFullMemoryInformation             = 25,
    SystemLoadGdiDriverInformation          = 26,
    SystemUnloadGdiDriverInformation        = 27,
    SystemTimeAdjustmentInformation         = 28,
    SystemSummaryMemoryInformation          = 29,
    SystemMirrorMemoryInformation           = 30,
    SystemPerformanceTraceInformation       = 31,
    SystemObsolete0                         = 32,
    SystemExceptionInformation              = 33,
    SystemCrashDumpStateInformation         = 34,
    SystemKernelDebuggerInformation         = 35,
    SystemContextSwitchInformation          = 36,
    SystemRegistryQuotaInformation          = 37,
    SystemExtendServiceTableInformation     = 38,
    SystemPrioritySeperation                = 39,
    SystemVerifierAddDriverInformation      = 40,
    SystemVerifierRemoveDriverInformation   = 41,
    SystemProcessorIdleInformation          = 42,
    SystemLegacyDriverInformation           = 43,
    SystemCurrentTimeZoneInformation        = 44,
    SystemLookasideInformation              = 45,
    SystemTimeSlipNotification              = 46,
    SystemSessionCreate                     = 47,
    SystemSessionDetach                     = 48,
    SystemSessionInformation                = 49,
    SystemRangeStartInformation             = 50,
    SystemVerifierInformation               = 51,
    SystemVerifierThunkExtend               = 52,
    SystemSessionProcessInformation         = 53,
    SystemLoadGdiDriverInSystemSpace        = 54,
    SystemNumaProcessorMap                  = 55,
    SystemPrefetcherInformation             = 56,
    SystemExtendedProcessInformation        = 57,
    SystemRecommendedSharedDataAlignment    = 58,
    SystemComPlusPackage                    = 59,
    SystemNumaAvailableMemory               = 60,
    SystemProcessorPowerInformation         = 61,
    SystemEmulationBasicInformation         = 62,
    SystemEmulationProcessorInformation     = 63,
    SystemExtendedHandleInformation         = 64,
    SystemLostDelayedWriteInformation       = 65,
    SystemBigPoolInformation                = 66,
    SystemSessionPoolTagInformation         = 67,
    SystemSessionMappedViewInformation      = 68,
    SystemHotpatchInformation               = 69,
    SystemObjectSecurityMode                = 70,
    SystemWatchdogTimerHandler              = 71,
    SystemWatchdogTimerInformation          = 72,
    SystemLogicalProcessorInformation       = 73,
    SystemWow64SharedInformation            = 74,
    SystemRegisterFirmwareTableInformationHandler = 75,
    SystemFirmwareTableInformation          = 76,
    SystemModuleInformationEx               = 77,
    SystemVerifierTriageInformation         = 78,
    SystemSuperfetchInformation             = 79,
    SystemMemoryListInformation             = 80,
    SystemFileCacheInformationEx            = 81,
    MaxSystemInfoClass                      = 82
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY
{
    ULONG Unknow1;
    ULONG Unknow2;
    ULONG Unknow3;
    ULONG Unknow4;
    PVOID DllBase;
    ULONG Size;
    ULONG Flags;
    USHORT Index;
    USHORT NameLength;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    char ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY, * PSYSTEM_MODULE_INFORMATION_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG Count;
    SYSTEM_MODULE_INFORMATION_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef NTSTATUS(WINAPI* pNtQuerySystemInformation)(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID                   SystemInformation,
    IN ULONG                    SystemInformationLength,
    OUT PULONG                  ReturnLength
);


typedef struct _KIWI_BUFFER {
    size_t* szBuffer;
    PWSTR* Buffer;
} KIWI_BUFFER, * PKIWI_BUFFER;

typedef enum _KIWI_OS_INDEX {
    KiwiOsIndex_UNK = 0,
    KiwiOsIndex_XP = 1,
    KiwiOsIndex_2K3 = 2,
    KiwiOsIndex_VISTA = 3,
    KiwiOsIndex_7 = 4,
    KiwiOsIndex_8 = 5,
    KiwiOsIndex_BLUE = 6,
    KiwiOsIndex_10_1507 = 7,
    KiwiOsIndex_10_1511 = 8,
    KiwiOsIndex_10_1607 = 9,
    KiwiOsIndex_10_1703 = 10,
    KiwiOsIndex_10_1709 = 11,
    KiwiOsIndex_10_1803 = 12,
    KiwiOsIndex_10_1809 = 13,
    KiwiOsIndex_10_1903 = 14,
    KiwiOsIndex_10_1909 = 15,
    KiwiOsIndex_10_2004 = 16,
    KiwiOsIndex_MAX = 17,
} KIWI_OS_INDEX, * PKIWI_OS_INDEX;

#if defined(_M_X64) || defined(_M_ARM64) // TODO:ARM64
#define EX_FAST_REF_MASK	0x0f
#elif defined(_M_IX86)
#define EX_FAST_REF_MASK	0x07
#endif

extern KIWI_OS_INDEX OsIndex;

typedef enum _KIWI_PROCESS_INDEX {
    EprocessNext = 0,
    EprocessFlags2 = 1,
    TokenPrivs = 2,
    SignatureProtect = 3,
    Eprocess_MAX = 4,
} KIWI_PROCESS_INDEX, * PKIWI_PROCESS_INDEX;

typedef enum _PS_PROTECTED_TYPE {
    PsProtectedTypeNone = 0,
    PsProtectedTypeProtectedLight = 1,
    PsProtectedTypeProtected = 2
} PS_PROTECTED_TYPE, * PPS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER {
    PsProtectedSignerNone = 0,
    PsProtectedSignerAuthenticode,
    PsProtectedSignerCodeGen,
    PsProtectedSignerAntimalware,
    PsProtectedSignerLsa,
    PsProtectedSignerWindows,
    PsProtectedSignerWinTcb,
    PsProtectedSignerWinSystem,
    PsProtectedSignerApp,
    PsProtectedSignerMax
} PS_PROTECTED_SIGNER, * PPS_PROTECTED_SIGNER;

const ULONG EPROCESS_OffSetTable[KiwiOsIndex_MAX][Eprocess_MAX] =
{					/*  EprocessNext, EprocessFlags2, TokenPrivs, SignatureProtect */
                    /*  dt nt!_EPROCESS -n ActiveProcessLinks -n Flags2 -n SignatureLevel */
#if defined(_M_IX86)
    /* UNK	*/{ 0 },
    /* XP	*/{ 0x0088 },
    /* 2K3	*/{ 0x0098 },
    /* VISTA*/{ 0x00a0, 0x0224, 0x0040 },
    /* 7	*/{ 0x00b8, 0x026c, 0x0040 },
    /* 8	*/{ 0x00b8, 0x00c0, 0x0040, 0x02d4 },
    /* BLUE	*/{ 0x00b8, 0x00c0, 0x0040, 0x02cc },
    /* 10_1507*/{ 0x00b8, 0x00c0, 0x0040, 0x02dc },
    /* 10_1511*/{ 0x00b8, 0x00c0, 0x0040, 0x02dc },
    /* 10_1607*/{ 0x00b8, 0x00c0, 0x0040, 0x02ec },
    /* 10_1703*/{ 0x00b8, 0x00c0, 0x0040, 0x02ec },
    /* 10_1709*/{ 0x00b8, 0x00c0, 0x0040, 0x02ec },
    /* 10_1803*/{ 0x00b8, 0x00c0, 0x0040, 0x02ec },
    /* 10_1809*/{ 0x00b8, 0x00c8, 0x0040, 0x02f4 },
    /* 10_1903*/{ 0x00b8, 0x00c8, 0x0040, 0x0364 },
#else
    /* UNK	*/{ 0 },
    /* XP	*/{ 0 },
    /* 2K3	*/{ 0x00e0 },
    /* VISTA*/{ 0x00e8, 0x036c, 0x0040 },
    /* 7	*/{ 0x0188, 0x043c, 0x0040 },
    /* 8	*/{ 0x02e8, 0x02f8, 0x0040, 0x0648 },
    /* BLUE	*/{ 0x02e8, 0x02f8, 0x0040, 0x0678 },
    /* 10_1507*/{ 0x02f0, 0x0300, 0x0040, 0x06a8 },
    /* 10_1511*/{ 0x02f0, 0x0300, 0x0040, 0x06b0 },
    /* 10_1607*/{ 0x02f0, 0x0300, 0x0040, 0x06c8 },
    /* 10_1703*/{ 0x02e8, 0x0300, 0x0040, 0x06c8 },
    /* 10_1709*/{ 0x02e8, 0x0300, 0x0040, 0x06c8 },
    /* 10_1803*/{ 0x02e8, 0x0300, 0x0040, 0x06c8 },
    /* 10_1809*/{ 0x02e8, 0x0300, 0x0040, 0x06c8 },
    /* 10_1903*/{ 0x02f0, 0x0308, 0x0040, 0x06f8 },
    /* 10_1909*/{ 0x02f0, 0x0308, 0x0040, 0x06f8 },
    /* 10_2004*/{ 0x0448, 0x0460, 0x0040, 0x0878}
#endif
};

typedef struct _PS_PROTECTION {
    UCHAR Type : 3;
    UCHAR Audit : 1;
    UCHAR Signer : 4;
} PS_PROTECTION, * PPS_PROTECTION;

typedef struct _KIWI_PROCESS_SIGNATURE_PROTECTION {
    UCHAR SignatureLevel;
    UCHAR SectionSignatureLevel;
    PS_PROTECTION Protection;
} KIWI_PROCESS_SIGNATURE_PROTECTION, * PKIWI_PROCESS_SIGNATURE_PROTECTION;


typedef struct _MIMIDRV_PROCESS_PROTECT_INFORMATION {
    HANDLE processId;
    KIWI_PROCESS_SIGNATURE_PROTECTION SignatureProtection;
} MIMIDRV_PROCESS_PROTECT_INFORMATION, * PMIMIDRV_PROCESS_PROTECT_INFORMATION;


#define PROTECTED_PROCESS_MASK	0x00000800

#define SystemHandleInformation 0x10
#define SystemHandleInformationSize 1024 * 1024 * 2

NTSTATUS ProtectProcessByPPL(SIZE_T szBufferIn, PVOID bufferIn);

// handle information
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

// handle table information
typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _PEB_LDR_DATA
{
    ULONG Length; // +
    UCHAR Initialized; // +
    PVOID SsHandle; // +
    LIST_ENTRY InLoadOrderModuleList; // +0x10 https://www.vergiliusproject.com/kernels/x64/Windows%2010%20%7C%202016/1607%20Redstone%201%20(Anniversary%20Update)/_PEB_LDR_DATA
    LIST_ENTRY InMemoryOrderModuleList; // +
    LIST_ENTRY InInitializationOrderModuleList;// +
} PEB_LDR_DATA, * PPEB_LDR_DATA; // +

struct _LDR_DATA_TABLE_ENTRY
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING FullDllName;                                     //0x48
    struct _UNICODE_STRING BaseDllName;                                     //0x58
    union
    {
        UCHAR FlagGroup[4];                                                 //0x68
        ULONG Flags;                                                        //0x68
        struct
        {
            ULONG PackagedBinary : 1;                                         //0x68
            ULONG MarkedForRemoval : 1;                                       //0x68
            ULONG ImageDll : 1;                                               //0x68
            ULONG LoadNotificationsSent : 1;                                  //0x68
            ULONG TelemetryEntryProcessed : 1;                                //0x68
            ULONG ProcessStaticImport : 1;                                    //0x68
            ULONG InLegacyLists : 1;                                          //0x68
            ULONG InIndexes : 1;                                              //0x68
            ULONG ShimDll : 1;                                                //0x68
            ULONG InExceptionTable : 1;                                       //0x68
            ULONG ReservedFlags1 : 2;                                         //0x68
            ULONG LoadInProgress : 1;                                         //0x68
            ULONG LoadConfigProcessed : 1;                                    //0x68
            ULONG EntryProcessed : 1;                                         //0x68
            ULONG ProtectDelayLoad : 1;                                       //0x68
            ULONG ReservedFlags3 : 2;                                         //0x68
            ULONG DontCallForThreads : 1;                                     //0x68
            ULONG ProcessAttachCalled : 1;                                    //0x68
            ULONG ProcessAttachFailed : 1;                                    //0x68
            ULONG CorDeferredValidate : 1;                                    //0x68
            ULONG CorImage : 1;                                               //0x68
            ULONG DontRelocate : 1;                                           //0x68
            ULONG CorILOnly : 1;                                              //0x68
            ULONG ChpeImage : 1;                                              //0x68
            ULONG ReservedFlags5 : 2;                                         //0x68
            ULONG Redirected : 1;                                             //0x68
            ULONG ReservedFlags6 : 2;                                         //0x68
            ULONG CompatDatabaseProcessed : 1;                                //0x68
        };
    };
    USHORT ObsoleteLoadCount;                                               //0x6c
    USHORT TlsIndex;                                                        //0x6e
    struct _LIST_ENTRY HashLinks;                                           //0x70
    ULONG TimeDateStamp;                                                    //0x80
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
    VOID* Lock;                                                             //0x90
    struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
    struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
    struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
    VOID* ParentDllBase;                                                    //0xb8
    VOID* SwitchBackContext;                                                //0xc0
};
