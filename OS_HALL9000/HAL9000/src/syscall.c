#include "HAL9000.h"
#include "syscall.h"
#include "gdtmu.h"
#include "syscall_defs.h"
#include "syscall_func.h"
#include "syscall_no.h"
#include "dmp_cpu.h"
#include "process_internal.h"
#include "thread.h"
#include "mmu.h"
#include "cpumu.h"
#include "smp.h"
#include "thread.h"
#include "thread_internal.h"

extern void SyscallEntry();

void
SyscallHandler(
    INOUT   COMPLETE_PROCESSOR_STATE    *CompleteProcessorState
    )
{
    SYSCALL_ID sysCallId;
    PQWORD pSyscallParameters;
    STATUS status;
    REGISTER_AREA* usermodeProcessorState;

    ASSERT(CompleteProcessorState != NULL);

    // It is NOT ok to setup the FMASK so that interrupts will be enabled when the system call occurs
    // The issue is that we'll have a user-mode stack and we wouldn't want to receive an interrupt on
    // that stack. This is why we only enable interrupts here.
    ASSERT(CpuIntrGetState() == INTR_OFF);
    CpuIntrSetState(INTR_ON);

    LOG_TRACE_USERMODE("The syscall handler has been called!\n");

    status = STATUS_SUCCESS;
    pSyscallParameters = NULL;
    usermodeProcessorState = &CompleteProcessorState->RegisterArea;

    __try
    {
        if (LogIsComponentTraced(LogComponentUserMode))
        {
            DumpProcessorState(CompleteProcessorState);
        }

        sysCallId = usermodeProcessorState->RegisterValues[RegisterR8];

        // The first parameter is the system call ID, we don't care about it => +1
        pSyscallParameters = (PQWORD)usermodeProcessorState->RegisterValues[RegisterRbp] + 1;

		switch (sysCallId)
		{
		case SyscallIdIdentifyVersion:
			status = SyscallValidateInterface((SYSCALL_IF_VERSION)pSyscallParameters[0]);
			break;
		case SyscallIdFileWrite:
			status = SyscallFileWrite(
				(UM_HANDLE)pSyscallParameters[0],
				(PVOID)pSyscallParameters[1],
				(QWORD)pSyscallParameters[2],
				(QWORD*)pSyscallParameters[3]);
			break;
		case SyscallIdProcessExit:
			status = SyscallProcessExit((STATUS)pSyscallParameters[0]);
			break;
		case SyscallIdProcessGetPid:
			status = SyscallProcessGetPid(
				(UM_HANDLE)pSyscallParameters[0],
				(PID*)pSyscallParameters[1]
			);
			break;
		case SyscallIdThreadExit:
			status = SyscallThreadExit(
				(STATUS)pSyscallParameters[0]
			);
			break;
		case SyscallIdSetAffinity:
			status = SyscallSetAffinity(
				(BYTE)pSyscallParameters[0]
			);
			break;
		case SyscallIdGetCurrentPcpuId:
			status = SyscallGetCurrentPcpuId(
				(BYTE*)pSyscallParameters[0]
			);
			break;
		case SyscallIdGetAffinity:
			status = SyscallGetAffinity(
				(BYTE*)pSyscallParameters[0]
			);
			break;
		default:
			break;
		}
    }
    __finally
    {
        LOG_TRACE_USERMODE("Will set UM RAX to 0x%x\n", status);

        usermodeProcessorState->RegisterValues[RegisterRax] = status;

        CpuIntrSetState(INTR_OFF);
    }
}

void
SyscallPreinitSystem(
    void
    )
{

}

STATUS
SyscallInitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

STATUS
SyscallUninitSystem(
    void
    )
{
    return STATUS_SUCCESS;
}

void
SyscallCpuInit(
    void
    )
{
    IA32_STAR_MSR_DATA starMsr;
    WORD kmCsSelector;
    WORD umCsSelector;

    memzero(&starMsr, sizeof(IA32_STAR_MSR_DATA));

    kmCsSelector = GdtMuGetCS64Supervisor();
    ASSERT(kmCsSelector + 0x8 == GdtMuGetDS64Supervisor());

    umCsSelector = GdtMuGetCS32Usermode();
    /// DS64 is the same as DS32
    ASSERT(umCsSelector + 0x8 == GdtMuGetDS32Usermode());
    ASSERT(umCsSelector + 0x10 == GdtMuGetCS64Usermode());

    // Syscall RIP <- IA32_LSTAR
    __writemsr(IA32_LSTAR, (QWORD) SyscallEntry);

    LOG_TRACE_USERMODE("Successfully set LSTAR to 0x%X\n", (QWORD) SyscallEntry);

    // Syscall RFLAGS <- RFLAGS & ~(IA32_FMASK)
    __writemsr(IA32_FMASK, RFLAGS_INTERRUPT_FLAG_BIT);

    LOG_TRACE_USERMODE("Successfully set FMASK to 0x%X\n", RFLAGS_INTERRUPT_FLAG_BIT);

    // Syscall CS.Sel <- IA32_STAR[47:32] & 0xFFFC
    // Syscall DS.Sel <- (IA32_STAR[47:32] + 0x8) & 0xFFFC
    starMsr.SyscallCsDs = kmCsSelector;

    // Sysret CS.Sel <- (IA32_STAR[63:48] + 0x10) & 0xFFFC
    // Sysret DS.Sel <- (IA32_STAR[63:48] + 0x8) & 0xFFFC
    starMsr.SysretCsDs = umCsSelector;

    __writemsr(IA32_STAR, starMsr.Raw);

    LOG_TRACE_USERMODE("Successfully set STAR to 0x%X\n", starMsr.Raw);
}

STATUS
SyscallValidateInterface(
	IN  SYSCALL_IF_VERSION          InterfaceVersion
)
{
	return InterfaceVersion == SYSCALL_IMPLEMENTED_IF_VERSION ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

STATUS
SyscallFileWrite(
	IN  UM_HANDLE                   FileHandle,
	IN_READS_BYTES(BytesToWrite)
	PVOID                       Buffer,
	IN  QWORD                       BytesToWrite,
	OUT QWORD* BytesWritten
)
{
	if (FileHandle == UM_FILE_HANDLE_STDOUT)
	{
		LOG("[%s]:[%s]\n", ProcessGetName(GetCurrentProcess()), Buffer);
	}
	else
	{
		return STATUS_UNSUCCESSFUL;
	}

	*BytesWritten = BytesToWrite;
	return STATUS_SUCCESS;
}

STATUS
SyscallProcessExit(
	IN      STATUS                  ExitStatus
)
{
	// terminate the current process
	ProcessTerminate(GetCurrentProcess());

	// return the ExitStatus
	return ExitStatus;
}

STATUS
SyscallProcessGetPid(
	IN_OPT  UM_HANDLE               ProcessHandle,
	OUT     PID* ProcessId
) {

	UNREFERENCED_PARAMETER(ProcessHandle);

	ASSERT_INFO(ProcessId != NULL, "The Process Id field can not be null!\n");

	// return the PID fof the current process if the file handles is UM_INVALID_HANDLE_VALUE
	if (ProcessHandle == UM_INVALID_HANDLE_VALUE) {
		*ProcessId = GetCurrentProcess()->Id;
		return STATUS_SUCCESS;
	}
	else {
		///TODO
		LOGPL("ALO, TREBE SA REFACI ASTA IN MOMENTUL IN CARE IMPLEMENTEZI FILE HANDLERS\n");
		return STATUS_UNSUCCESSFUL;
	}
}

// Thread exit
STATUS
SyscallThreadExit(
	IN      STATUS                  ExitStatus
) {
	ThreadExit(ExitStatus);

	return STATUS_SUCCESS;
}

STATUS
SyscallSetAffinity(
	IN  BYTE Affinity
)
{
	// validate that the new mask allows the current thread to run on at least a PCPU
	if ((Affinity & SmpGetSystemAffinity()) == 0) {
		return STATUS_UNSUCCESSFUL;
	}
	
	// set affinity
	PTHREAD currentThread = GetCurrentThread();
	currentThread->ThreadAffinityMask = Affinity;
	
	// recompute PCPU on which the thread could be run on
	ThreadSetPossibleRunnablePcpu(currentThread);

	// move the thread on the correct PCPU
	ThreadYield();

	return STATUS_SUCCESS;
}

STATUS
SyscallGetAffinity(
	OUT BYTE* Affinity
) {
	// validate that the input parameter is not null
	if (Affinity == NULL) {
		return STATUS_UNSUCCESSFUL;
	}

	// validate that the buffer is valid
	if (!SUCCEEDED(MmuIsBufferValid(Affinity, sizeof(BYTE), PAGE_RIGHTS_WRITE, GetCurrentProcess()))) {
		return STATUS_UNSUCCESSFUL;
	}

	// get current thread
	PTHREAD currentThread = GetCurrentThread();

	// set affinity
	*Affinity = currentThread->ThreadAffinityMask;

	return STATUS_SUCCESS;
}

STATUS
SyscallGetCurrentPcpuId(
	OUT BYTE* PcpuId
)
{
	// validate that the input parameter is not null
	if (PcpuId == NULL) {
		return STATUS_UNSUCCESSFUL;
	}

	// validate that the buffer is valid
	if (!SUCCEEDED(MmuIsBufferValid(PcpuId, sizeof(BYTE), PAGE_RIGHTS_WRITE, GetCurrentProcess()))) {
		return STATUS_UNSUCCESSFUL;
	}

	*PcpuId = GetCurrentPcpu()->LogicalApicId;

	return STATUS_SUCCESS;
}
