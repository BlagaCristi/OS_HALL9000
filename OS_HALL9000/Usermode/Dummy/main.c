#include "common_lib.h"
#include "syscall_if.h"
#include "um_lib_helper.h"

STATUS
__main(
    DWORD       argc,
    char**      argv
)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

	STATUS status;

	LOG("Test will start\n");

	BYTE affinity, pcpuId;
	status = SyscallGetAffinity(&affinity);

	if (!SUCCEEDED(status)) {
		LOG("SyscallGetAffinity failed...\n");
		return STATUS_UNSUCCESSFUL;
	}

	status = SyscallGetCurrentPcpuId(&pcpuId);
	if (!SUCCEEDED(status)) {
		LOG("SyscallGetCurrentPcpuId failed...\n");
		return STATUS_UNSUCCESSFUL;
	}

	LOG("Initial affinity is %d; thread on PCPU %d\n", affinity, pcpuId);

	for (DWORD i = 0; i < 8; i++) {
		affinity = 1 << i;
		LOG("Will move thread on the affinity: %d\n", affinity);
		
		status = SyscallSetAffinity(affinity);
		if (!SUCCEEDED(status)) {
			LOG("SyscallSetAffinity failed...\n");
			return STATUS_UNSUCCESSFUL;
		}

		status = SyscallGetAffinity(&affinity);
		if (!SUCCEEDED(status)) {
			LOG("SyscallGetAffinity failed...\n");
			return STATUS_UNSUCCESSFUL;
		}

		status = SyscallGetCurrentPcpuId(&pcpuId);
		if (!SUCCEEDED(status)) {
			LOG("SyscallGetCurrentPcpuId failed...\n");
			return STATUS_UNSUCCESSFUL;
		}
		LOG("Thread moved; Current affinity is %d; thread on PCPU %d\n", affinity, pcpuId);
	}

	affinity = 41;
	LOG("Will move thread on the affinity: %d\n", affinity);

	status = SyscallSetAffinity(affinity);
	if (!SUCCEEDED(status)) {
		LOG("SyscallSetAffinity failed...\n");
		return STATUS_UNSUCCESSFUL;
	}

	status = SyscallGetAffinity(&affinity);
	if (!SUCCEEDED(status)) {
		LOG("SyscallGetAffinity failed...\n");
		return STATUS_UNSUCCESSFUL;
	}

	status = SyscallGetCurrentPcpuId(&pcpuId);
	if (!SUCCEEDED(status)) {
		LOG("SyscallGetCurrentPcpuId failed...\n");
		return STATUS_UNSUCCESSFUL;
	}
	LOG("Thread moved; Current affinity is %d; thread on PCPU %d\n", affinity, pcpuId);


    return STATUS_SUCCESS;
}