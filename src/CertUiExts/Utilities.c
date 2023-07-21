#include "pch.h"

#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>

#include <wincrypt.h>

#include "Shared.h"

#include "CertUiExts.h"

#ifdef _DEBUG
#include <stdarg.h>
#include <assert.h>

#define DEBUG_BUFFER_SIZE 1024

CHAR pszDebugBuffer[DEBUG_BUFFER_SIZE];
CHAR* pszDebugStringPrefix = "[%-25s] ";

void OutputDebugFormatStringA(const LPCSTR pszFuncName, const LPCSTR pszDebugFormat, ...) {
    va_list args;
    size_t stDebugStringOffset;
    size_t stDebugStringSize = sizeof(CHAR); // Terminating null

    va_start(args, pszDebugFormat);

    if (sprintf_s(pszDebugBuffer, DEBUG_BUFFER_SIZE, pszDebugStringPrefix, pszFuncName) == -1) {
        goto end;
    }

    stDebugStringOffset = strnlen_s(pszDebugBuffer, DEBUG_BUFFER_SIZE);
    stDebugStringSize += _scprintf(pszDebugStringPrefix, pszFuncName) * sizeof(CHAR);
    stDebugStringSize += _vscprintf(pszDebugFormat, args) * sizeof(CHAR);

    if (stDebugStringSize <= DEBUG_BUFFER_SIZE) {
        if (vsprintf_s(&pszDebugBuffer[stDebugStringOffset / sizeof(CHAR)],
                       stDebugStringSize - stDebugStringOffset,
                       pszDebugFormat, args) < 0) {
            goto end;
        }
    } else {
        if (strcat_s(&pszDebugBuffer[stDebugStringOffset / sizeof(CHAR)],
                     stDebugStringSize - stDebugStringOffset,
                     "Formatted string exceeds debug buffer size.\n") != 0) {
            goto end;
        }
    }

    OutputDebugStringA(pszDebugBuffer);

end:
    va_end(args);
}

void FormatObjectDebugEntryA(const LPCSTR pszFuncName,
                             const DWORD dwCertEncodingType,
                             const DWORD dwFormatStrType,
                             const LPCSTR lpszStructType,
                             const DWORD cbFormat) {
    int ret;
    int cbDebugStringOffset = 0;

    assert(dwCertEncodingType == X509_ASN_ENCODING);

    ret = sprintf_s(pszDebugBuffer,
                    DEBUG_BUFFER_SIZE,
                    pszDebugStringPrefix, pszFuncName);
    if (ret != -1) { cbDebugStringOffset += ret; }

    ret = sprintf_s(&pszDebugBuffer[cbDebugStringOffset / sizeof(CHAR)],
                    DEBUG_BUFFER_SIZE - cbDebugStringOffset - 1,
                    "dwFormatStrType: %u", dwFormatStrType);
    if (ret != -1) { cbDebugStringOffset += ret; }

    if ((size_t)lpszStructType >> 16 == 0) {
        ret = sprintf_s(&pszDebugBuffer[cbDebugStringOffset / sizeof(CHAR)],
                        DEBUG_BUFFER_SIZE - cbDebugStringOffset - 1,
                        ", lpszStructType: %zu", (size_t)lpszStructType & 0xFFFF);
    } else {
        ret = sprintf_s(&pszDebugBuffer[cbDebugStringOffset / sizeof(CHAR)],
                        DEBUG_BUFFER_SIZE - cbDebugStringOffset - 1,
                        ", lpszStructType: %s", lpszStructType);
    }
    if (ret != -1) { cbDebugStringOffset += ret; }

    ret = sprintf_s(&pszDebugBuffer[cbDebugStringOffset / sizeof(CHAR)],
                    DEBUG_BUFFER_SIZE - cbDebugStringOffset - 1,
                    ", pcbFormat: %u", cbFormat);
    if (ret != -1) { cbDebugStringOffset += ret; }

    if (strcat_s(&pszDebugBuffer[cbDebugStringOffset / sizeof(CHAR)],
                 DEBUG_BUFFER_SIZE - cbDebugStringOffset - 1,
                 "\n") == 0) {
        OutputDebugStringA(pszDebugBuffer);
    }
}

void FormatObjectDebugExitA(const LPCSTR pszFuncName, const BOOL bStatus) {
    int ret;
    int cbDebugStringOffset = 0;

    // Only output on exit for failures
    if (bStatus) { return; }

    ret = sprintf_s(pszDebugBuffer,
                    DEBUG_BUFFER_SIZE,
                    pszDebugStringPrefix, pszFuncName);
    if (ret != -1) { cbDebugStringOffset += ret; }

    ret = sprintf_s(&pszDebugBuffer[cbDebugStringOffset / sizeof(CHAR)],
                    DEBUG_BUFFER_SIZE - cbDebugStringOffset - 1,
                    "Return status: %s", bStatus ? "true" : "false");
    if (ret != -1) { cbDebugStringOffset += ret; }

    if (strcat_s(&pszDebugBuffer[cbDebugStringOffset / sizeof(CHAR)],
                 DEBUG_BUFFER_SIZE - cbDebugStringOffset - 1,
                 "\n") == 0) {
        OutputDebugStringA(pszDebugBuffer);
    }
}
#endif

BOOL ConvertGuidToStringW(const GUID* pGuid, LPWSTR* ppwszGuid) {
    const DWORD dwGuidChars = dwGUID_SIZE_CHARS + 1; // Add terminating null

    *ppwszGuid = calloc(dwGuidChars, sizeof(WCHAR));
    if (*ppwszGuid == NULL) {
        DBG_PRINT("calloc() failed to allocate WCHAR array for GUID (errno: %d)\n", errno);
        return FALSE;
    }

    if (swprintf_s(*ppwszGuid,
                   dwGuidChars,
                   L"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                   pGuid->Data1, pGuid->Data2, pGuid->Data3,
                   pGuid->Data4[0], pGuid->Data4[1], pGuid->Data4[2], pGuid->Data4[3],
                   pGuid->Data4[4], pGuid->Data4[5], pGuid->Data4[6], pGuid->Data4[7]) != -1) {
        return TRUE;
    }

    DBG_PRINT("swprintf_s() failed to format GUID (errno: %d)\n", errno);

    free(*ppwszGuid);
    *ppwszGuid = NULL;

    return FALSE;
}

BOOL DecodeAsnGuid(const BYTE* pbEncoded, const DWORD cbEncoded, GUID** ppGuid) {
    BOOL bStatus = FALSE;
    CRYPT_INTEGER_BLOB* pbAsnGuidBlob = NULL;
    DWORD cbAsnGuidBlob = 0;

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING,
                             X509_OCTET_STRING,
                             pbEncoded,
                             cbEncoded,
                             CRYPT_DECODE_ALLOC_FLAG,
                             NULL, // Use LocalAlloc()
                             &pbAsnGuidBlob,
                             &cbAsnGuidBlob)) {
        DBG_PRINT("CryptDecodeObjectEx() failed (err: %u)\n", GetLastError());
        return bStatus;
    }

    if (pbAsnGuidBlob->cbData != sizeof(GUID)) {
        DBG_PRINT("Decoded ASN.1 octet string has %u bytes but expected %u bytes\n",
                  pbAsnGuidBlob->cbData, (DWORD)sizeof(GUID));
        goto end;
    }

    *ppGuid = malloc(sizeof(GUID));
    if (*ppGuid == NULL) {
        DBG_PRINT("malloc() failed to allocate %u bytes (errno: %d)\n", (DWORD)sizeof(GUID), errno);
        goto end;
    }

    if (memcpy_s(*ppGuid, sizeof(GUID), pbAsnGuidBlob->pbData, pbAsnGuidBlob->cbData) != 0) {
        DBG_PRINT("memcpy_s() failed copying decoded GUID (errno: %d)\n", errno);
        free(*ppGuid);
        *ppGuid = NULL;
        goto end;
    }

    bStatus = TRUE;

end:
    LocalFree(pbAsnGuidBlob);

    return bStatus;
}

BOOL DecodeAsnSidA(const BYTE* pbEncoded, const DWORD cbEncoded, LPSTR* ppszSid, DWORD* cbSid) {
    BOOL bStatus = FALSE;
    CRYPT_INTEGER_BLOB* pbAsnSidBlob = NULL;
    DWORD cbAsnSidBlob = 0;
    DWORD cbSidLenA;

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING,
                             X509_OCTET_STRING,
                             pbEncoded,
                             cbEncoded,
                             CRYPT_DECODE_ALLOC_FLAG,
                             NULL, // Use LocalAlloc()
                             &pbAsnSidBlob,
                             &cbAsnSidBlob)) {
        DBG_PRINT("CryptDecodeObjectEx() failed (err: %u)\n", GetLastError());
        return bStatus;
    }

    cbSidLenA = pbAsnSidBlob->cbData + sizeof(CHAR); // Add terminating null
    *ppszSid = calloc(cbSidLenA, sizeof(CHAR));
    if (*ppszSid == NULL) {
        DBG_PRINT("calloc() failed to allocate CHAR array for SID (errno: %d)\n", errno);
        goto end;
    }

    if (strncpy_s(*ppszSid, cbSidLenA, (CHAR*)pbAsnSidBlob->pbData, pbAsnSidBlob->cbData) != 0) {
        DBG_PRINT("strncpy_s() failed copying decoded SID bytes (errno: %d)\n", errno);
        free(*ppszSid);
        *ppszSid = NULL;
        goto end;
    }

    *cbSid = cbSidLenA;
    bStatus = TRUE;

end:
    LocalFree(pbAsnSidBlob);

    return bStatus;
}

BOOL FormatAsGuidStringW(const DWORD dwFormatStrType,
                         const BYTE* pbEncoded,
                         const DWORD cbEncoded,
                         void* pbFormat,
                         DWORD* pcbFormat) {
    BOOL bStatus = FALSE;
    GUID* pGuid = NULL;
    LPWSTR pwszGuid = NULL;

    // Add newline & terminating null
    const DWORD dwBufferSize = (dwGUID_SIZE_CHARS + 2) * sizeof(WCHAR);

    if (SetFormatBufferSize(pbFormat, pcbFormat, dwBufferSize)) {
        return TRUE;
    }

    if (!VerifyFormatBufferSize(pcbFormat, dwBufferSize)) {
        return FALSE;
    }

    if (*pcbFormat < dwBufferSize) {
        DBG_PRINT("Output buffer must be at least %u bytes but is %u bytes\n", dwBufferSize, *pcbFormat);
        *pcbFormat = dwBufferSize;
        SetLastError(ERROR_MORE_DATA);
        goto end;
    }

    if (!DecodeAsnGuid(pbEncoded, cbEncoded, &pGuid)) {
        goto end;
    }

    if (!ConvertGuidToStringW(pGuid, &pwszGuid)) {
        goto end;
    }

    if (swprintf_s(pbFormat, *pcbFormat / sizeof(WCHAR), L"%s\n", pwszGuid) == -1) {
        DBG_PRINT("swprintf_s() failed to format GUID to output buffer (errno: %d)\n", errno);
        goto end;
    }

    bStatus = TRUE;

end:
    free(pwszGuid);
    free(pGuid);

    return bStatus ? TRUE : SetFailureInfo(dwFormatStrType, pbFormat, pcbFormat);
}

/*
 * The exported functions matching the CryptFormatObject() prototype can be
 * called with dwFormatStrType having CRYPT_FORMAT_STR_MULTI_LINE set. When not
 * set, this typically means the output is being formatted for a value field in
 * a list view. If so, it's generally better to return a failure message as the
 * output, otherwise the field will simply be blank.
 */
BOOL SetFailureInfo(const DWORD dwFormatStrType, void* pbFormat, const DWORD* pcbFormat) {
    if (dwFormatStrType == 0) {
        if (*pcbFormat >= sizeof(wszFORMAT_FAILURE)) {
            if (wcscpy_s(pbFormat, *pcbFormat / sizeof(WCHAR), wszFORMAT_FAILURE) == 0) {
                return TRUE;
            }

            DBG_PRINT("wcscpy_s() failed copying string to output buffer (errno: %d)\n", errno);
            return FALSE;
        }

        DBG_PRINT("Format function failed and output buffer of %u bytes insufficient for failure string\n", *pcbFormat);
    }

    return FALSE;
}

/*
 * The exported functions matching the CryptFormatObject() prototype can be
 * called with pbFormat set to NULL, in which case pcbFormat should be set to
 * the required size of the buffer provided in pbFormat. The documentation is
 * unclear as to the return value in this scenario.
 *
 * Observations from testing:
 * - When called to populate the certificate UI list view (dwFormatStrType:
 *   NULL) the return value is ignored.
 * - When called to populate the certificate UI text view (dwFormatStrType:
 *   CRYPT_FORMAT_STR_MULTI_LINE | CRYPT_FORMAT_STR_NO_HEX) the return value
 *   must be TRUE.
 */
BOOL SetFormatBufferSize(const void* pbFormat, DWORD* pcbFormat, const DWORD dwSize) {
    if (pbFormat != NULL || *pcbFormat != 0) {
        return FALSE;
    }

    *pcbFormat = dwSize;
    SetLastError(ERROR_MORE_DATA);
    return TRUE;
}

/*
 * Verifies the size of the provided buffer is sufficient for the data to be
 * returned. While SetFormatBufferSize() sets the required buffer size when the
 * caller is probing for the size, this function will check the provided buffer
 * in the subsequent call is actually sufficient as an additional safety check.
 * It's probably redundant as subsequent calls in the formatting function will
 * fail, but it means we fail sooner and assists with debugging caller issues.
 */
BOOL VerifyFormatBufferSize(const DWORD* pcbFormat, const DWORD dwSize) {
    if (*pcbFormat <= dwSize) {
        return TRUE;
    }

    DBG_PRINT("Output buffer must be at least %u bytes but is %u bytes\n", dwSize, *pcbFormat);
    SetLastError(ERROR_MORE_DATA);
    return FALSE;
}
