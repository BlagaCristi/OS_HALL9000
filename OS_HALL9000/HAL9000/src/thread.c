#include "HAL9000.h"
#include "thread_internal.h"
#include "synch.h"
#include "cpumu.h"
#include "ex_event.h"
#include "core.h"
#include "vmm.h"
#include "process_internal.h"
#include "isr.h"
#include "gdtmu.h"
#include "pe_exports.h"
#include "smp.h"

#define TID_INCREMENT               4

#define THREAD_TIME_SLICE           1

extern void ThreadStart();

typedef
void
(__cdecl FUNC_ThreadSwitch)(
    OUT_PTR         PVOID*          OldStack,
    IN              PVOID           NewStack
    );

extern FUNC_ThreadSwitch            ThreadSwitch;

typedef struct _THREAD_SYSTEM_DATA
{
    LOCK                AllThreadsLock;

    _Guarded_by_(AllThreadsLock)
    LIST_ENTRY          AllThreadsList;
} THREAD_SYSTEM_DATA, *PTHREAD_SYSTEM_DATA;

static THREAD_SYSTEM_DATA m_threadSystemData;

__forceinline
static
TID
_ThreadSystemGetNextTid(
    void
    )
{
    static volatile TID __currentTid = 0;

    return _InterlockedExchangeAdd64(&__currentTid, TID_INCREMENT);
}

static
STATUS
_ThreadInit(
    IN_Z        char*               Name,
    IN          THREAD_PRIORITY     Priority,
    OUT_PTR     PTHREAD*            Thread,
    IN          BOOLEAN             AllocateKernelStack,
	IN			BYTE				ThreadAffinity
    );

static
STATUS
_ThreadSetupInitialState(
    IN      PTHREAD             Thread,
    IN      PVOID               StartFunction,
    IN      QWORD               FirstArgument,
    IN      QWORD               SecondArgument,
    IN      BOOLEAN             KernelStack
    );

static
STATUS
_ThreadSetupMainThreadUserStack(
    IN      PVOID               InitialStack,
    OUT     PVOID*              ResultingStack,
    IN      PPROCESS            Process
    );


REQUIRES_EXCL_LOCK(GetCurrentPcpu()->PCpuReadyListLock)
RELEASES_EXCL_AND_NON_REENTRANT_LOCK(GetCurrentPcpu()->PCpuReadyListLock)
static
void
_ThreadSchedule(
    void
    );

void
ThreadCleanupPostSchedule(
    void
    );

REQUIRES_EXCL_LOCK(GetCurrentPcpu()->PCpuReadyListLock)
static
_Ret_notnull_
PTHREAD
_ThreadGetReadyThread(
    void
    );

static
void
_ThreadForcedExit(
    void
    );

static
void
_ThreadReference(
    INOUT   PTHREAD                 Thread
    );

static
void
_ThreadDereference(
    INOUT   PTHREAD                 Thread
    );

static FUNC_FreeFunction            _ThreadDestroy;

static
void
_ThreadKernelFunction(
    IN      PFUNC_ThreadStart       Function,
    IN_OPT  PVOID                   Context
    );

static FUNC_ThreadStart     _IdleThread;

void
_No_competing_thread_
ThreadSystemPreinit(
    void
    )
{
    memzero(&m_threadSystemData, sizeof(THREAD_SYSTEM_DATA));

    InitializeListHead(&m_threadSystemData.AllThreadsList);
    LockInit(&m_threadSystemData.AllThreadsLock);
}

static
unsigned int
_random_generator(unsigned int upperBound) {

	/*
	* Pseudo number generator
	* Generates numbers between 0 and upperBound - 1.
	*/

	static long holdrand = 1L;

	return (((holdrand = holdrand * 214013L + 2531011L) >> 16) & 0x7fff) % upperBound;
}

STATUS
ThreadSystemInitMainForCurrentCPU(
    void
    )
{
    STATUS status;
    PPCPU pCpu;
    char mainThreadName[MAX_PATH];
    PTHREAD pThread;
    PPROCESS pProcess;

    LOG_FUNC_START;

    status = STATUS_SUCCESS;
    pCpu = GetCurrentPcpu();
    pThread = NULL;
    pProcess = ProcessRetrieveSystemProcess();

    ASSERT( NULL != pCpu );

    snprintf( mainThreadName, MAX_PATH, "%s-%02x", "main", pCpu->ApicId );

    status = _ThreadInit(mainThreadName, ThreadPriorityDefault, &pThread, FALSE, MAX_BYTE);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("_ThreadInit", status );
        return status;
    }
    LOGPL("_ThreadInit succeeded\n");

    pThread->InitialStackBase = pCpu->StackTop;
    pThread->StackSize = pCpu->StackSize;

    pThread->State = ThreadStateRunning;
    SetCurrentThread(pThread);

    // In case of the main thread of the BSP the process will be NULL so we need to handle that case
    // When the system process will be initialized it will insert into its thread list the current thread (which will
    // be the main thread of the BSP)
    if (pProcess != NULL)
    {
        ProcessInsertThreadInList(pProcess, pThread);
    }

    LOG_FUNC_END;

    return status;
}

STATUS
ThreadSystemInitIdleForCurrentCPU(
    void
    )
{
    EX_EVENT idleStarted;
    STATUS status;
    PPCPU pCpu;
    char idleThreadName[MAX_PATH];
    PTHREAD idleThread;

    ASSERT( INTR_OFF == CpuIntrGetState() );

    LOG_FUNC_START_THREAD;

    status = STATUS_SUCCESS;
    pCpu = GetCurrentPcpu();

    ASSERT(NULL != pCpu);

    status = ExEventInit(&idleStarted, ExEventTypeSynchronization, FALSE);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("EvtInitialize", status);
        return status;
    }
    LOGPL("EvtInitialize succeeded\n");

    snprintf(idleThreadName, MAX_PATH, "%s-%02x", "idle", pCpu->ApicId);

    // create idle thread
    status = ThreadCreate(idleThreadName,
                          ThreadPriorityDefault,
                          _IdleThread,
                          &idleStarted,
                          &idleThread,
						  MAX_BYTE
                          );
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("ThreadCreate", status);
        return status;
    }
    LOGPL("ThreadCreate for IDLE thread succeeded\n");

    ThreadCloseHandle(idleThread);
    idleThread = NULL;

    LOGPL("About to enable interrupts\n");

    // lets enable some interrupts :)
    CpuIntrEnable();

    LOGPL("Interrupts enabled :)\n");

    // wait for idle thread
    LOG_TRACE_THREAD("Waiting for idle thread signal\n");
    ExEventWaitForSignal(&idleStarted);
    LOG_TRACE_THREAD("Received idle thread signal\n");

    LOG_FUNC_END_THREAD;

    return status;
}

STATUS
ThreadCreate(
    IN_Z        char*               Name,
    IN          THREAD_PRIORITY     Priority,
    IN          PFUNC_ThreadStart   Function,
    IN_OPT      PVOID               Context,
    OUT_PTR     PTHREAD*            Thread,
	IN			BYTE				ThreadAffinity
    )
{
    return ThreadCreateEx(Name,
                          Priority,
                          Function,
                          Context,
                          Thread,
                          ProcessRetrieveSystemProcess(),
						  ThreadAffinity);
}

STATUS
ThreadCreateEx(
    IN_Z        char*               Name,
    IN          THREAD_PRIORITY     Priority,
    IN          PFUNC_ThreadStart   Function,
    IN_OPT      PVOID               Context,
    OUT_PTR     PTHREAD*            Thread,
    INOUT       struct _PROCESS*    Process,
	IN			BYTE				ThreadAffinity
    )
{
    STATUS status;
    PTHREAD pThread;
    PPCPU pCpu;
    BOOLEAN bProcessIniialThread;
    PVOID pStartFunction;
    QWORD firstArg;
    QWORD secondArg;

    if (NULL == Name)
    {
        return STATUS_INVALID_PARAMETER1;
    }

    if (NULL == Function)
    {
        return STATUS_INVALID_PARAMETER3;
    }

    if (NULL == Thread)
    {
        return STATUS_INVALID_PARAMETER5;
    }

    if (NULL == Process)
    {
        return STATUS_INVALID_PARAMETER6;
    }

	if ((ThreadAffinity & SmpGetSystemAffinity()) == 0 && SmpGetSystemAffinity() != 0)
	{
		return STATUS_INVALID_PARAMETER7;
	}

    status = STATUS_SUCCESS;
    pThread = NULL;
    pCpu = GetCurrentPcpu();
    bProcessIniialThread = FALSE;
    pStartFunction = NULL;
    firstArg = 0;
    secondArg = 0;

    ASSERT(NULL != pCpu);

    status = _ThreadInit(Name, Priority, &pThread, TRUE, ThreadAffinity);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("_ThreadInit", status);
        return status;
    }

    ProcessInsertThreadInList(Process, pThread);

    // the reference must be done outside _ThreadInit
    _ThreadReference(pThread);

    if (!Process->PagingData->Data.KernelSpace)
    {
        // Create user-mode stack
        pThread->UserStack = MmuAllocStack(STACK_DEFAULT_SIZE,
                                           TRUE,
                                           FALSE,
                                           Process);
        if (pThread->UserStack == NULL)
        {
            status = STATUS_MEMORY_CANNOT_BE_COMMITED;
            LOG_FUNC_ERROR_ALLOC("MmuAllocStack", STACK_DEFAULT_SIZE);
            return status;
        }

        bProcessIniialThread = (Function == Process->HeaderInfo->Preferred.AddressOfEntryPoint);

        // We are the first thread => we must pass the argc and argv parameters
        // and the whole command line which spawned the process
        if (bProcessIniialThread)
        {
            // It's one because we already incremented it when we called ProcessInsertThreadInList earlier
            ASSERT(Process->NumberOfThreads == 1);

            status = _ThreadSetupMainThreadUserStack(pThread->UserStack,
                                                     &pThread->UserStack,
                                                     Process);
            if (!SUCCEEDED(status))
            {
                LOG_FUNC_ERROR("_ThreadSetupUserStack", status);
                return status;
            }
        }
        else
        {
            pThread->UserStack = (PVOID) PtrDiff(pThread->UserStack, SHADOW_STACK_SIZE + sizeof(PVOID));
        }

        pStartFunction = (PVOID) (bProcessIniialThread ? Process->HeaderInfo->Preferred.AddressOfEntryPoint : Function);
        firstArg       = (QWORD) (bProcessIniialThread ? Process->NumberOfArguments : (QWORD) Context);
        secondArg      = (QWORD) (bProcessIniialThread ? PtrOffset(pThread->UserStack, SHADOW_STACK_SIZE + sizeof(PVOID)) : 0);
    }
    else
    {
        // Kernel mode

        // warning C4152: nonstandard extension, function/data pointer conversion in expression
#pragma warning(suppress:4152)
        pStartFunction = _ThreadKernelFunction;

        firstArg =  (QWORD) Function;
        secondArg = (QWORD) Context;
    }

    status = _ThreadSetupInitialState(pThread,
                                      pStartFunction,
                                      firstArg,
                                      secondArg,
                                      Process->PagingData->Data.KernelSpace);
    if (!SUCCEEDED(status))
    {
        LOG_FUNC_ERROR("_ThreadSetupInitialState", status);
        return status;
    }

    if (NULL == pCpu->ThreadData.IdleThread)
    {
        pThread->State = ThreadStateReady;

        // this is the IDLE thread creation
        pCpu->ThreadData.IdleThread = pThread;
    }
    else
    {
        ThreadUnblock(pThread);
    }

    *Thread = pThread;

    return status;
}

void
ThreadTick(
    void
    )
{
    PPCPU pCpu = GetCurrentPcpu();
    PTHREAD pThread = GetCurrentThread();

    ASSERT( INTR_OFF == CpuIntrGetState());
    ASSERT( NULL != pCpu);

    LOG_TRACE_THREAD("Thread tick\n");
    if (pCpu->ThreadData.IdleThread == pThread)
    {
        pCpu->ThreadData.IdleTicks++;
    }
    else
    {
        pCpu->ThreadData.KernelTicks++;
    }
    pThread->TickCountCompleted++;

    if (++pCpu->ThreadData.RunningThreadTicks >= THREAD_TIME_SLICE)
    {
        LOG_TRACE_THREAD("Will yield on return\n");
        pCpu->ThreadData.YieldOnInterruptReturn = TRUE;
    }
}

void
ThreadYield(
    void
    )
{
    INTR_STATE dummyState;
    INTR_STATE oldState;
    PTHREAD pThread = GetCurrentThread();
    PPCPU pCpu;
    BOOLEAN bForcedYield;

    ASSERT( NULL != pThread);

    oldState = CpuIntrDisable();

    pCpu = GetCurrentPcpu();

    ASSERT( NULL != pCpu );

    bForcedYield = pCpu->ThreadData.YieldOnInterruptReturn;
    pCpu->ThreadData.YieldOnInterruptReturn = FALSE;

    if (THREAD_FLAG_FORCE_TERMINATE_PENDING == _InterlockedAnd(&pThread->Flags, MAX_DWORD))
    {
        _ThreadForcedExit();
        NOT_REACHED;
    }

	pThread->State = ThreadStateReady;

	// if thread different than idle thread
    if (pThread != pCpu->ThreadData.IdleThread)
    {
		PLIST_ENTRY pCpuListEntry;
		SmpGetCpuList(&pCpuListEntry);

		// get the CPU where the current thread can run
		PLIST_ENTRY currentPcpuEntry = GetListElemByIndex(pCpuListEntry, pThread->PcpuIndex);
		pCpu = CONTAINING_RECORD(currentPcpuEntry, PCPU, ListEntry);

		// insert the thread in that CPU's ready list
		LockAcquire(&pCpu->PCpuReadyListLock, &dummyState);
		InsertTailList(&pCpu->PCpuReadyList, &pThread->ReadyList);
		LockRelease(&pCpu->PCpuReadyListLock, dummyState);
    }
	LockAcquire(&GetCurrentPcpu()->PCpuReadyListLock, &dummyState);
    if (!bForcedYield)
    {
        pThread->TickCountEarly++;
    }
	_ThreadSchedule();
    ASSERT( !LockIsOwner(&GetCurrentPcpu()->PCpuReadyListLock));
    LOG_TRACE_THREAD("Returned from _ThreadSchedule\n");

    CpuIntrSetState(oldState);
}

void
ThreadBlock(
    void
    )
{
    INTR_STATE oldState;
    PTHREAD pCurrentThread;

    pCurrentThread = GetCurrentThread();

    ASSERT( INTR_OFF == CpuIntrGetState());
    ASSERT(LockIsOwner(&pCurrentThread->BlockLock));

    if (THREAD_FLAG_FORCE_TERMINATE_PENDING == _InterlockedAnd(&pCurrentThread->Flags, MAX_DWORD))
    {
        _ThreadForcedExit();
        NOT_REACHED;
    }


    pCurrentThread->TickCountEarly++;
    pCurrentThread->State = ThreadStateBlocked;
    LockAcquire(&GetCurrentPcpu()->PCpuReadyListLock, &oldState);
	//LOGPL("Blocked %x\n", pCurrentThread);
    _ThreadSchedule();
    ASSERT( !LockIsOwner(&GetCurrentPcpu()->PCpuReadyListLock));
}

void
ThreadUnblock(
    IN      PTHREAD              Thread
    )
{
    INTR_STATE oldState;
    INTR_STATE dummyState;

    ASSERT(NULL != Thread);

    LockAcquire(&Thread->BlockLock, &oldState);

    ASSERT(ThreadStateBlocked == Thread->State);

	Thread->State = ThreadStateReady;

	PLIST_ENTRY pCpuListEntry;
	SmpGetCpuList(&pCpuListEntry);

	// retrieve the CPU where the thread can run
	PLIST_ENTRY currentPcpuEntry = GetListElemByIndex(pCpuListEntry, Thread->PcpuIndex);
	PPCPU pCpu = CONTAINING_RECORD(currentPcpuEntry, PCPU, ListEntry);

	// insert the thread in the CPU's ready list
    LockAcquire(&pCpu->PCpuReadyListLock, &dummyState);
    InsertTailList(&pCpu->PCpuReadyList, &Thread->ReadyList);
    LockRelease(&pCpu->PCpuReadyListLock, dummyState );
    LockRelease(&Thread->BlockLock, oldState);
}

void
ThreadExit(
    IN      STATUS              ExitStatus
    )
{
    PTHREAD pThread;
    INTR_STATE oldState;

    LOG_FUNC_START_THREAD;

    pThread = GetCurrentThread();

    CpuIntrDisable();

    if (LockIsOwner(&pThread->BlockLock))
    {
        LockRelease(&pThread->BlockLock, INTR_OFF);
    }

    pThread->State = ThreadStateDying;
    pThread->ExitStatus = ExitStatus;
    ExEventSignal(&pThread->TerminationEvt);

    ProcessNotifyThreadTermination(pThread);

    LockAcquire(&GetCurrentPcpu()->PCpuReadyListLock, &oldState);
    _ThreadSchedule();
    NOT_REACHED;
}

BOOLEAN
ThreadYieldOnInterrupt(
    void
    )
{
    return GetCurrentPcpu()->ThreadData.YieldOnInterruptReturn;
}

void
ThreadTakeBlockLock(
    void
    )
{
    INTR_STATE dummyState;

    LockAcquire(&GetCurrentThread()->BlockLock, &dummyState);
}

void
ThreadWaitForTermination(
    IN      PTHREAD             Thread,
    OUT     STATUS*             ExitStatus
    )
{
    ASSERT( NULL != Thread );
    ASSERT( NULL != ExitStatus);

    ExEventWaitForSignal(&Thread->TerminationEvt);

    *ExitStatus = Thread->ExitStatus;
}

void
ThreadCloseHandle(
    INOUT   PTHREAD             Thread
    )
{
    ASSERT( NULL != Thread);

    _ThreadDereference(Thread);
}

void
ThreadTerminate(
    INOUT   PTHREAD             Thread
    )
{
    ASSERT( NULL != Thread );

    // it's not a problem if the thread already finished
    _InterlockedOr(&Thread->Flags, THREAD_FLAG_FORCE_TERMINATE_PENDING );
}

const
char*
ThreadGetName(
    IN_OPT  PTHREAD             Thread
    )
{
    PTHREAD pThread = (NULL != Thread) ? Thread : GetCurrentThread();

    return (NULL != pThread) ? pThread->Name : "";
}

TID
ThreadGetId(
    IN_OPT  PTHREAD             Thread
    )
{
    PTHREAD pThread = (NULL != Thread) ? Thread : GetCurrentThread();

    return (NULL != pThread) ? pThread->Id : 0;
}

THREAD_PRIORITY
ThreadGetPriority(
    IN_OPT  PTHREAD             Thread
    )
{
    PTHREAD pThread = (NULL != Thread) ? Thread : GetCurrentThread();

    return (NULL != pThread) ? pThread->Priority : 0;
}

void
ThreadSetPriority(
    IN      THREAD_PRIORITY     NewPriority
    )
{
    ASSERT(ThreadPriorityLowest <= NewPriority && NewPriority <= ThreadPriorityMaximum);

    GetCurrentThread()->Priority = NewPriority;
}

STATUS
ThreadExecuteForEachThreadEntry(
    IN      PFUNC_ListFunction  Function,
    IN_OPT  PVOID               Context
    )
{
    STATUS status;
    INTR_STATE oldState;

    if (NULL == Function)
    {
        return STATUS_INVALID_PARAMETER1;
    }

    status = STATUS_SUCCESS;

    LockAcquire(&m_threadSystemData.AllThreadsLock, &oldState);
    status = ForEachElementExecute(&m_threadSystemData.AllThreadsList,
                                   Function,
                                   Context,
                                   FALSE
                                   );
    LockRelease(&m_threadSystemData.AllThreadsLock, oldState );

    return status;
}

void
SetCurrentThread(
    IN      PTHREAD     Thread
    )
{
    PPCPU pCpu;

    __writemsr(IA32_FS_BASE_MSR, Thread);

    pCpu = GetCurrentPcpu();
    ASSERT(pCpu != NULL);

    pCpu->ThreadData.CurrentThread = Thread->Self;
    if (NULL != Thread->Self)
    {
        pCpu->StackTop = Thread->InitialStackBase;
        pCpu->StackSize = Thread->StackSize;
        pCpu->Tss.Rsp[0] = (QWORD) Thread->InitialStackBase;
    }
}

static
STATUS
_ThreadInit(
    IN_Z        char*               Name,
    IN          THREAD_PRIORITY     Priority,
    OUT_PTR     PTHREAD*            Thread,
    IN          BOOLEAN             AllocateKernelStack,
	IN			BYTE				ThreadAffinity
    )
{
    STATUS status;
    PTHREAD pThread;
    DWORD nameLen;
    PVOID pStack;
    INTR_STATE oldIntrState;

    LOG_FUNC_START;

    ASSERT(NULL != Name);
    ASSERT(NULL != Thread);
	ASSERT((ThreadAffinity & SmpGetSystemAffinity()) || SmpGetSystemAffinity() == 0);
    ASSERT_INFO(ThreadPriorityLowest <= Priority && Priority <= ThreadPriorityMaximum,
                "Priority is 0x%x\n", Priority);

    status = STATUS_SUCCESS;
    pThread = NULL;
    nameLen = strlen(Name);
    pStack = NULL;

    __try
    {
        pThread = ExAllocatePoolWithTag(PoolAllocateZeroMemory, sizeof(THREAD), HEAP_THREAD_TAG, 0);
        if (NULL == pThread)
        {
            LOG_FUNC_ERROR_ALLOC("HeapAllocatePoolWithTag", sizeof(THREAD));
            status = STATUS_HEAP_INSUFFICIENT_RESOURCES;
            __leave;
        }

        RfcPreInit(&pThread->RefCnt);

        status = RfcInit(&pThread->RefCnt, _ThreadDestroy, NULL);
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("RfcInit", status);
            __leave;
        }

        pThread->Self = pThread;

        status = ExEventInit(&pThread->TerminationEvt, ExEventTypeNotification, FALSE);
        if (!SUCCEEDED(status))
        {
            LOG_FUNC_ERROR("ExEventInit", status);
            __leave;
        }

        if (AllocateKernelStack)
        {
            pStack = MmuAllocStack(STACK_DEFAULT_SIZE, TRUE, FALSE, NULL);
            if (NULL == pStack)
            {
                LOG_FUNC_ERROR_ALLOC("MmuAllocStack", STACK_DEFAULT_SIZE);
                status = STATUS_MEMORY_CANNOT_BE_COMMITED;
                __leave;
            }
            pThread->Stack = pStack;
            pThread->InitialStackBase = pStack;
            pThread->StackSize = STACK_DEFAULT_SIZE;
        }

        pThread->Name = ExAllocatePoolWithTag(PoolAllocateZeroMemory, sizeof(char)*(nameLen + 1), HEAP_THREAD_TAG, 0);
        if (NULL == pThread->Name)
        {
            LOG_FUNC_ERROR_ALLOC("HeapAllocatePoolWithTag", sizeof(char)*(nameLen + 1));
            status = STATUS_HEAP_INSUFFICIENT_RESOURCES;
            __leave;
        }

        strcpy(pThread->Name, Name);

        pThread->Id = _ThreadSystemGetNextTid();
        pThread->State = ThreadStateBlocked;
        pThread->Priority = Priority;

        LockInit(&pThread->BlockLock);

        LockAcquire(&m_threadSystemData.AllThreadsLock, &oldIntrState);
        InsertTailList(&m_threadSystemData.AllThreadsList, &pThread->AllList);
        LockRelease(&m_threadSystemData.AllThreadsLock, oldIntrState);

		// set current thread's affinity
		pThread->ThreadAffinityMask = ThreadAffinity;

		// set current thread's possible runnable PCPU
		ThreadSetPossibleRunnablePcpu(pThread);
    }
    __finally
    {
        if (!SUCCEEDED(status))
        {
            if (NULL != pThread)
            {
                _ThreadDereference(pThread);
                pThread = NULL;
            }
        }

        *Thread = pThread;

        LOG_FUNC_END;
    }

    return status;
}

//  STACK TOP
//  -----------------------------------------------------------------
//  |                                                               |
//  |       Shadow Space                                            |
//  |                                                               |
//  |                                                               |
//  -----------------------------------------------------------------
//  |     Dummy Function RA                                         |
//  ---------------------------------------------------------------------------------
//  |     SS     = DS64Supervisor        | DS64Usermode             |               |
//  -----------------------------------------------------------------               |
//  |     RSP    = &(Dummy Function RA)  | Thread->UserStack        |               |
//  -----------------------------------------------------------------               |
//  |     RFLAGS = RFLAGS_IF | RFLAGS_RESERVED                      |   Interrupt   |
//  -----------------------------------------------------------------     Stack     |
//  |     CS     = CS64Supervisor        | CS64Usermode             |               |
//  -----------------------------------------------------------------               |
//  |     RIP    = _ThreadKernelFunction | AddressOfEntryPoint      |               |
//  ---------------------------------------------------------------------------------
//  |     Thread Start Function                                     |
//  -----------------------------------------------------------------
//  |                                                               |
//  |       PROCESSOR_STATE                                         |
//  |                                                               |
//  |                                                               |
//  -----------------------------------------------------------------
//  STACK BASE <- RSP at ThreadSwitch
static
STATUS
_ThreadSetupInitialState(
    IN      PTHREAD             Thread,
    IN      PVOID               StartFunction,
    IN      QWORD               FirstArgument,
    IN      QWORD               SecondArgument,
    IN      BOOLEAN             KernelStack
    )
{
    STATUS status;
    PVOID* pStack;
    PCOMPLETE_PROCESSOR_STATE pState;
    PINTERRUPT_STACK pIst;

    ASSERT( NULL != Thread );
    ASSERT( NULL != StartFunction);

    status = STATUS_SUCCESS;

    pStack = (PVOID*) Thread->Stack;

    // The kernel function has to have a shadow space and a dummy RA
    pStack = pStack - ( 4 + 1 );

    pStack = (PVOID*) PtrDiff(pStack, sizeof(INTERRUPT_STACK));

    // setup pseudo-interrupt stack
    pIst = (PINTERRUPT_STACK) pStack;

    pIst->Rip = (QWORD) StartFunction;
    if (KernelStack)
    {
        pIst->CS = GdtMuGetCS64Supervisor();
        pIst->Rsp = (QWORD)(pIst + 1);
        pIst->SS = GdtMuGetDS64Supervisor();
    }
    else
    {
        ASSERT(Thread->UserStack != NULL);

        pIst->CS = GdtMuGetCS64Usermode() | RING_THREE_PL;
        pIst->Rsp = (QWORD) Thread->UserStack;
        pIst->SS = GdtMuGetDS64Usermode() | RING_THREE_PL;
    }

    pIst->RFLAGS = RFLAGS_INTERRUPT_FLAG_BIT | RFLAGS_RESERVED_BIT;

    pStack = pStack - 1;

    // warning C4054: 'type cast': from function pointer 'void (__cdecl *)(const PFUNC_ThreadStart,const PVOID)' to data pointer 'PVOID'
#pragma warning(suppress:4054)
    *pStack = (PVOID) ThreadStart;

    pStack = (PVOID*) PtrDiff(pStack, sizeof(COMPLETE_PROCESSOR_STATE));
    pState = (PCOMPLETE_PROCESSOR_STATE) pStack;

    memzero(pState, sizeof(COMPLETE_PROCESSOR_STATE));
    pState->RegisterArea.RegisterValues[RegisterRcx] = FirstArgument;
    pState->RegisterArea.RegisterValues[RegisterRdx] = SecondArgument;

    Thread->Stack = pStack;

    return STATUS_SUCCESS;
}


//  USER STACK TOP
//  -----------------------------------------------------------------
//  |                       Argument N-1                            |
//  -----------------------------------------------------------------
//  |                          ...                                  |
//  -----------------------------------------------------------------
//  |                       Argument 0                              |
//  -----------------------------------------------------------------
//  |                 argv[N-1] = &(Argument N-1)                   |
//  -----------------------------------------------------------------
//  |                          ...                                  |
//  -----------------------------------------------------------------
//  |                 argv[0] = &(Argument 0)                       |
//  -----------------------------------------------------------------
//  |                 Dummy 4th Arg = 0xDEADBEEF                    |
//  -----------------------------------------------------------------
//  |                 Dummy 3rd Arg = 0xDEADBEEF                    |
//  -----------------------------------------------------------------
//  |                 argv = &argv[0]                               |
//  -----------------------------------------------------------------
//  |                 argc = N (Process->NumberOfArguments)         |
//  -----------------------------------------------------------------
//  |                 Dummy RA = 0xDEADC0DE                         |
//  -----------------------------------------------------------------
//  USER STACK BASE
static
STATUS
_ThreadSetupMainThreadUserStack(
    IN      PVOID               InitialStack,
    OUT     PVOID*              ResultingStack,
    IN      PPROCESS            Process
    )
{
	ASSERT(InitialStack != NULL);
	ASSERT(ResultingStack != NULL);
	ASSERT(Process != NULL);

	DWORD argumentsMemoryTag = 1000;
	DWORD argumentMemoryTag = 1001;

	char** arguments = ExAllocatePoolWithTag(PoolAllocateZeroMemory, Process->NumberOfArguments * sizeof(char*), argumentsMemoryTag, 0);
	const char* currentPointer, * previousPointer;

	unsigned int argumentNumber = 0;

	previousPointer = Process->FullCommandLine;
	currentPointer = strchr(Process->FullCommandLine, ' ');

	while (argumentNumber < Process->NumberOfArguments - 1) {

		unsigned int argumentPos = Process->NumberOfArguments - 1 - argumentNumber;
		__int64 argumentLength = currentPointer - previousPointer + 1;

		arguments[argumentPos] = ExAllocatePoolWithTag(PoolAllocateZeroMemory, (DWORD)(argumentLength * sizeof(char)), argumentMemoryTag + argumentNumber, 0);
		strncpy(arguments[argumentPos], previousPointer, (DWORD)(argumentLength - 1)); // sets the NULL by itself on the argumentLength position

		argumentNumber++;
		previousPointer = currentPointer + 1; //go over the space
		currentPointer = strchr(previousPointer, ' ');
	}

	__int64 argumentLength = Process->FullCommandLine + strlen(Process->FullCommandLine) - previousPointer + 1;

	arguments[0] = ExAllocatePoolWithTag(PoolAllocateZeroMemory, (DWORD)(argumentLength * sizeof(char)), argumentMemoryTag + argumentNumber, 0);
	strncpy(arguments[0], previousPointer, (DWORD)(argumentLength - 1)); // sets the NULL by itself on the argumentLength position

	DWORD totalStackSize = 0;

	// add length of elements + their corresponding NULL terminators
	for (unsigned int i = 0; i < Process->NumberOfArguments; i++) {
		totalStackSize += strlen(arguments[i]) + 1;
	}

	// allign to 8 bytes
	int multiple8 = totalStackSize % 8;
	if (multiple8 != 0) {
		totalStackSize += (8 - multiple8);
	}

	// add addresses
	totalStackSize += sizeof(char*) * Process->NumberOfArguments;

	// add 2 shadow spaces
	totalStackSize += 2 * sizeof(void*);

	// add argv
	totalStackSize += sizeof(char**);

	// add argc
	totalStackSize += sizeof(QWORD);

	// add return address
	totalStackSize += sizeof(void*);

	// allign the return address to a multiple of 16
	int shouldJump = 0;
	if ((totalStackSize / 8) % 2 == 0) {
		shouldJump = 1;
		totalStackSize += 8;
	}

	// copy arguments' value in the stack
	// compute stack size along the way
	// we need to map the stack into the kernel space

	PVOID kernelStack = InitialStack;
	MmuGetSystemVirtualAddressForUserBuffer(
		(char*)PtrDiff(InitialStack, (QWORD)totalStackSize),
		totalStackSize,
		PAGE_RIGHTS_ALL,
		Process,
		&kernelStack
	);

	kernelStack = (char*)PtrOffset(kernelStack, (QWORD)totalStackSize);

	// copy the effective value of the arguments on the stack 
	DWORD stackSize = 0;

	for (unsigned int i = 0; i < Process->NumberOfArguments; i++) {
		stackSize += strlen(arguments[i]) + 1;

		strncpy((char*)PtrDiff(kernelStack, (QWORD)stackSize), arguments[i], strlen(arguments[i])); // will also add NULL
	}

	// allign to 8 bytes the stack size
	multiple8 = stackSize % 8;
	if (multiple8 != 0) {
		stackSize += (8 - multiple8);
	}

	// allign return address
	stackSize += shouldJump * 8;

	unsigned int argumentPos = 0;

	// copy the address of the arguments on the stack
	// CAREFUL -> the addresses are the ones from the InitialStack
	for (unsigned int i = 0; i < Process->NumberOfArguments; i++) {

		argumentPos += strlen(arguments[i]) + 1;
		//char* aux = (char*)kernelStack - argumentPos;
		char* aux = (char*)PtrDiff(InitialStack, (QWORD)argumentPos);

#pragma warning(disable:4311)
		QWORD value = (QWORD)aux;
		stackSize += sizeof(char*);

#pragma warning(disable:4244)
		* ((QWORD*)PtrDiff(kernelStack, (QWORD)stackSize)) = (QWORD)value;
	}

	// take address of argv0
	//char* aux = (char*)kernelStack - stackSize;
	char* aux = (char*)PtrDiff(InitialStack, (QWORD)stackSize);
	QWORD argvZero = (QWORD)aux;

	// add 2 shadow spaces
	stackSize += 2 * sizeof(void*);



	// insert argv0 address
	stackSize += sizeof(QWORD**);
	*((QWORD*)PtrDiff(kernelStack, (QWORD)stackSize)) = (QWORD)argvZero;

	// insert argc
	stackSize += sizeof(QWORD);
	*((QWORD*)PtrDiff(kernelStack, (QWORD)stackSize)) = (QWORD)Process->NumberOfArguments;

	// add return address
	stackSize += sizeof(void*);

	// UNCOMMENT the following code if you want to print the content of the stack along with the addresses from the UserSpace stack

	/*
	QWORD* stackk = (QWORD*)PtrDiff(kernelStack, (QWORD)totalStackSize);
	QWORD* stackkk = (QWORD*)PtrDiff(InitialStack, (QWORD)totalStackSize);
	for (unsigned int i = 0; i < totalStackSize / 8; i++) {
		LOG_TRACE_USERMODE("Stack stuff %d ; KernelStack: %x ; InitialStack :  %x\n", i, *stackk, stackkk);
		stackk = (QWORD*)PtrOffset(stackk, 8);
		stackkk = (QWORD*)PtrOffset(stackkk, 8);
	}
	*/


	MmuFreeSystemVirtualAddressForUserBuffer(
		(char*)PtrDiff(kernelStack, (QWORD)totalStackSize)
	);

	LOG_TRACE_USERMODE("Finished filling up the stack; stackSize: %d %d\n", totalStackSize, stackSize);

	*ResultingStack = (PVOID)PtrDiff(InitialStack, (QWORD)totalStackSize);

	return STATUS_SUCCESS;
}

REQUIRES_EXCL_LOCK(GetCurrentPcpu()->PCpuReadyListLock)
RELEASES_EXCL_AND_NON_REENTRANT_LOCK(GetCurrentPcpu()->PCpuReadyListLock)
static
void
_ThreadSchedule(
    void
    )
{
    PTHREAD pCurrentThread;
    PTHREAD pNextThread;

    ASSERT(INTR_OFF == CpuIntrGetState());
    ASSERT(LockIsOwner(&GetCurrentPcpu()->PCpuReadyListLock));

    pCurrentThread = GetCurrentThread();
    ASSERT( NULL != pCurrentThread );

    // save previous thread
	GetCurrentPcpu()->ThreadData.PreviousThread = pCurrentThread;

    // get next thread
    pNextThread = _ThreadGetReadyThread();
    ASSERT( NULL != pNextThread );

    // if current differs from next
    // => schedule next
    if (pNextThread != pCurrentThread)
    {
        LOG_TRACE_THREAD("Before ThreadSwitch\n");
        LOG_TRACE_THREAD("Current thread: %s\n", pCurrentThread->Name);
        LOG_TRACE_THREAD("Next thread: %s\n", pNextThread->Name);

        if (pCurrentThread->Process != pNextThread->Process)
        {
            MmuChangeProcessSpace(pNextThread->Process);
        }

        // Before any thread is scheduled it executes this function, thus if we set the current
        // thread to be the next one it will be fine - there is no possibility of interrupts
        // appearing to cause inconsistencies
        pCurrentThread->UninterruptedTicks = 0;

		LOGPL("Thread switch on core: %d; Previous thread: %x; Current thread: %x\n", GetCurrentPcpu()->ApicId, pCurrentThread, pNextThread);
        SetCurrentThread(pNextThread);
        ThreadSwitch( &pCurrentThread->Stack, pNextThread->Stack);
		LOGPL("Thread switch on core %d performed\n");

        ASSERT(INTR_OFF == CpuIntrGetState());

        LOG_TRACE_THREAD("After ThreadSwitch\n");
        LOG_TRACE_THREAD("Current: %s\n", pCurrentThread->Name);

        // We cannot log the name of the 'next thread', i.e. the thread which formerly preempted
        // this one because a long time may have passed since then and it may have been destroyed

        // The previous thread may also have been destroyed after it was de-scheduled, we have
        // to be careful before logging its name
        if (GetCurrentPcpu()->ThreadData.PreviousThread != NULL)
        {
            LOG_TRACE_THREAD("Prev thread: %s\n", GetCurrentPcpu()->ThreadData.PreviousThread->Name);
        }
    }
    else
    {
        pCurrentThread->UninterruptedTicks++;
    }

    ThreadCleanupPostSchedule();
}

void
ThreadCleanupPostSchedule(
    void
    )
{
    PTHREAD prevThread;

    ASSERT(INTR_OFF == CpuIntrGetState());

    GetCurrentPcpu()->ThreadData.RunningThreadTicks = 0;
    prevThread = GetCurrentPcpu()->ThreadData.PreviousThread;

    if (NULL != prevThread)
    {
        if (LockIsOwner(&prevThread->BlockLock))
        {
            // Unfortunately, we cannot use the inverse condition because it is not always
            // true, i.e. if the previous thread is the idle thread it's not 100% sure that
            // it was previously holding the block hold, it may have been preempted before
            // acquiring it.
            ASSERT(prevThread->State == ThreadStateBlocked
                   || prevThread == GetCurrentPcpu()->ThreadData.IdleThread);

            LOG_TRACE_THREAD("Will release block lock for thread [%s]\n", prevThread->Name);

            _Analysis_assume_lock_held_(prevThread->BlockLock);
            LockRelease(&prevThread->BlockLock, INTR_OFF);
        }
        else if (prevThread->State == ThreadStateDying)
        {
            LOG_TRACE_THREAD("Will dereference thread: [%s]\n", prevThread->Name);

            // dereference thread
            _ThreadDereference(prevThread);
            GetCurrentPcpu()->ThreadData.PreviousThread = NULL;
        }
    }
}

static
STATUS
(__cdecl _IdleThread)(
    IN_OPT      PVOID       Context
    )
{
    PEX_EVENT pEvent;

    LOG_FUNC_START_THREAD;

    ASSERT( NULL != Context);

    pEvent = (PEX_EVENT) Context;
    ExEventSignal(pEvent);

    // warning C4127: conditional expression is constant
#pragma warning(suppress:4127)
    while (TRUE)
    {
        CpuIntrDisable();
        ThreadTakeBlockLock();
        ThreadBlock();

        __sti_and_hlt();
    }

    NOT_REACHED;
}

REQUIRES_EXCL_LOCK(GetCurrentPcpu()->PCpuReadyListLock)
static
_Ret_notnull_
PTHREAD
_ThreadGetReadyThread(
    void
    )
{
    PTHREAD pNextThread;
    PLIST_ENTRY pEntry;
    BOOLEAN bIdleScheduled;
	INTR_STATE oldState;
    ASSERT( INTR_OFF == CpuIntrGetState());
    ASSERT( LockIsOwner(&GetCurrentPcpu()->PCpuReadyListLock));

    pNextThread = NULL;

    pEntry = RemoveHeadList(&GetCurrentPcpu()->PCpuReadyList);

	// In order to avoid deadlocks, we will release the lock here.
	// This is ok because, from this point onwards, we do not work with this list anymore.
	LockRelease(&GetCurrentPcpu()->PCpuReadyListLock, INTR_OFF);

	if (pEntry == &GetCurrentPcpu()->PCpuReadyList) // if the current PCPU's ready list is empty
	{
		/*
			Search for a thread in the other PCPU's lists
		*/

		// create random index list
		DWORD numberOfActiveCpus = SmpGetNumberOfActiveCpus();
		unsigned int index = _random_generator(numberOfActiveCpus);

		// traverse list forward
		BOOLEAN found = FALSE;
		PTHREAD foundPThread = NULL;
		PPCPU foundCore = NULL;
		PLIST_ENTRY pcpuList;
		SmpGetCpuList(&pcpuList);

		// for each PCPU
		for (DWORD i = 0; i < numberOfActiveCpus; i++) {
			
			// get index in list based on the randomly generated index
			DWORD listIndex = (i + index) % numberOfActiveCpus;
			
			// find current PCPU
			PLIST_ENTRY currentPcpuEntry = GetListElemByIndex(pcpuList, listIndex);
			PPCPU pCpu = CONTAINING_RECORD(currentPcpuEntry, PCPU, ListEntry);
			
			if (pCpu->LogicalApicId != GetCurrentPcpu()->LogicalApicId) { // if it is not the current PCPU

				// acquire lock
				LockAcquire(&pCpu->PCpuReadyListLock, &oldState);

				for (PLIST_ENTRY pCurEntry = (&pCpu->PCpuReadyList)->Flink;
					pCurEntry != (&pCpu->PCpuReadyList);
					pCurEntry = pCurEntry->Flink)
				{
					PTHREAD currentThread = CONTAINING_RECORD(pCurEntry, THREAD, ReadyList);
					if ((currentThread->ThreadAffinityMask & GetCurrentPcpu()->LogicalApicId) != 0) {
						foundPThread = currentThread;
						foundCore = pCpu;
						break;
					}
				}

				if (foundPThread != NULL) { // if it has threads ready to be executed
						
					// thread found
					found = TRUE;

					RemoveEntryList(&foundPThread->ReadyList);

					// release lock
					LockRelease(&pCpu->PCpuReadyListLock, oldState);
						
					// stop search
					break;
				}

				// no threads found in the current PCPU list => just release lock
				LockRelease(&pCpu->PCpuReadyListLock, oldState);
			}
		}

		if (!found) {// if none found => RETURN IDLE THREAD
			LOG_TRACE_THREAD("No thread found in any list => will run IDLE thread\n");
			// set next thread
			pNextThread = GetCurrentPcpu()->ThreadData.IdleThread;
			
			// set flag indicating that it is the IDLE thread
			bIdleScheduled = TRUE;
		}
		else { // if a thread has been found, then it is ready to be executed
			LOG_TRACE_THREAD("Thread found in another PCPU's list => will run it\n");

			LOGPL("Core: %d; Found thread on core: %d; Thread found: %x; I was running thread: %x; My idle thread is: %x\n", GetCurrentPcpu()->ApicId, foundCore->ApicId, foundPThread, GetCurrentPcpu()->ThreadData.CurrentThread, GetCurrentPcpu()->ThreadData.IdleThread);

			// set next thread
			pNextThread = foundPThread;
			
			// set flag indicating that it is not the IDLE thread
			bIdleScheduled = FALSE;

			// assert that the thread is ready to be executed
			ASSERT(pNextThread->State == ThreadStateReady);
		}
	}
    else // if the current's PCPU list was not empty
    {

		LOG_TRACE_THREAD("Thread found in current's PCPU list => will run it\n");
		// set next thread
		pNextThread = CONTAINING_RECORD( pEntry, THREAD, ReadyList );

		LOGPL("Core: %d; Found thread in my list; Thread found: %x; I was running thread: %x; My idle thread is: %x\n", GetCurrentPcpu()->ApicId, pNextThread, GetCurrentPcpu()->ThreadData.CurrentThread, GetCurrentPcpu()->ThreadData.IdleThread);

		// assert that the thread is ready to be executed
        ASSERT( pNextThread->State == ThreadStateReady );

		// set flag indicating that it is not the IDLE thread
        bIdleScheduled = FALSE;
    }

    // maybe we shouldn't update idle time each time a thread is scheduled
    // maybe it is enough only every x times
    // or maybe we can update time only on RTC updates
    CoreUpdateIdleTime(bIdleScheduled);

    return pNextThread;
}

static
void
_ThreadForcedExit(
    void
    )
{
    PTHREAD pCurrentThread = GetCurrentThread();

    _InterlockedOr( &pCurrentThread->Flags, THREAD_FLAG_FORCE_TERMINATED );

    ThreadExit(STATUS_JOB_INTERRUPTED);
    NOT_REACHED;
}

static
void
_ThreadReference(
    INOUT   PTHREAD                 Thread
    )
{
    ASSERT( NULL != Thread );

    RfcReference(&Thread->RefCnt);
}

static
void
_ThreadDereference(
    INOUT   PTHREAD                 Thread
    )
{
    ASSERT( NULL != Thread );

    RfcDereference(&Thread->RefCnt);
}

static
void
_ThreadDestroy(
    IN      PVOID                   Object,
    IN_OPT  PVOID                   Context
    )
{
    INTR_STATE oldState;
    PTHREAD pThread = (PTHREAD) Object;

    ASSERT(NULL != pThread);
    ASSERT(NULL == Context);

    LockAcquire(&m_threadSystemData.AllThreadsLock, &oldState);
    RemoveEntryList(&pThread->AllList);
    LockRelease(&m_threadSystemData.AllThreadsLock, oldState);

    // This must be done before removing the thread from the process list, else
    // this may be the last thread and the process VAS will be freed by the time
    // ProcessRemoveThreadFromList - this function also dereferences the process
    if (NULL != pThread->UserStack)
    {
        // Free UM stack
        MmuFreeStack(pThread->UserStack, pThread->Process);
        pThread->UserStack = NULL;
    }

    ProcessRemoveThreadFromList(pThread);

    if (NULL != pThread->Name)
    {
        ExFreePoolWithTag(pThread->Name, HEAP_THREAD_TAG);
        pThread->Name = NULL;
    }

    if (NULL != pThread->Stack)
    {
        // This is the kernel mode stack
        // It does not 'belong' to any process => pass NULL
        MmuFreeStack(pThread->Stack, NULL);
        pThread->Stack = NULL;
    }

    ExFreePoolWithTag(pThread, HEAP_THREAD_TAG);
}

static
void
_ThreadKernelFunction(
    IN      PFUNC_ThreadStart       Function,
    IN_OPT  PVOID                   Context
    )
{
    STATUS exitStatus;

    ASSERT(NULL != Function);

    CHECK_STACK_ALIGNMENT;

    ASSERT(CpuIntrGetState() == INTR_ON);
    exitStatus = Function(Context);

    ThreadExit(exitStatus);
    NOT_REACHED;
}

void
ThreadSetPossibleRunnablePcpu(
	IN PTHREAD	PThread
) {
	ASSERT(PThread != NULL);
	ASSERT((PThread->ThreadAffinityMask & SmpGetSystemAffinity()) || SmpGetSystemAffinity() == 0);

	PLIST_ENTRY pCpuListEntry;
	DWORD numberOfActivePcpu = SmpGetNumberOfActiveCpus();
	SmpGetCpuList(&pCpuListEntry);

	// find the first CPU where the given thread can run based on the thread's affinity mask
	for (DWORD index = 0; index < numberOfActivePcpu; index++) {
		PLIST_ENTRY currentPcpuEntry = GetListElemByIndex(pCpuListEntry, index);
		PPCPU pCpu = CONTAINING_RECORD(currentPcpuEntry, PCPU, ListEntry);
		
		// when found, save it
		if ((PThread->ThreadAffinityMask & pCpu->LogicalApicId) != 0) {
			PThread->PcpuIndex = index;
			break;
		}
	}
}