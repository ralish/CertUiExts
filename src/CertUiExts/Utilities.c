#include "pch.h"

#include <wincrypt.h>

#ifdef _DEBUG
#include <stdarg.h>
#include <assert.h>

#define DEBUG_BUFFER_SIZE (size_t)1024

CHAR pszDebugBuffer[DEBUG_BUFFER_SIZE];
CHAR* pszDebugStringPrefix = "[%-25s] ";

void OutputDebugFormatStringA(_In_z_ const PCSTR pszFuncName,
                              _Printf_format_string_ const PCSTR pszDebugFormat,
                              ...) {
    va_list args;
    size_t cbDebugStringOffset;
    size_t cbDebugStringSize = sizeof(CHAR); // Terminating null

    va_start(args, pszDebugFormat);

    if (sprintf_s(pszDebugBuffer, DEBUG_BUFFER_SIZE, pszDebugStringPrefix, pszFuncName) == -1) {
        goto end;
    }

    cbDebugStringOffset = strnlen_s(pszDebugBuffer, DEBUG_BUFFER_SIZE);
    cbDebugStringSize += _scprintf(pszDebugStringPrefix, pszFuncName) * sizeof(CHAR);
    cbDebugStringSize += _vscprintf(pszDebugFormat, args) * sizeof(CHAR);

    if (cbDebugStringSize <= DEBUG_BUFFER_SIZE) {
        if (vsprintf_s(&pszDebugBuffer[cbDebugStringOffset / sizeof(CHAR)],
                       cbDebugStringSize - cbDebugStringOffset,
                       pszDebugFormat, args) < 0) {
            goto end;
        }
    } else {
        if (strcat_s(&pszDebugBuffer[cbDebugStringOffset / sizeof(CHAR)],
                     cbDebugStringSize - cbDebugStringOffset,
                     "Formatted string exceeds debug buffer size.\n") != 0) {
            goto end;
        }
    }

    OutputDebugStringA(pszDebugBuffer);

end:
    va_end(args);
}

void FormatObjectDebugEntryA(_In_z_ const PCSTR pszFuncName,
                             _In_ const DWORD dwCertEncodingType,
                             _In_ const DWORD dwFormatStrType,
                             _In_z_ const PCSTR pszStructType,
                             _In_ const DWORD cbFormat) {
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

    if ((size_t)pszStructType >> 16 == 0) {
        ret = sprintf_s(&pszDebugBuffer[cbDebugStringOffset / sizeof(CHAR)],
                        DEBUG_BUFFER_SIZE - cbDebugStringOffset - 1,
                        ", lpszStructType: %zu", (size_t)pszStructType & 0xFFFF);
    } else {
        ret = sprintf_s(&pszDebugBuffer[cbDebugStringOffset / sizeof(CHAR)],
                        DEBUG_BUFFER_SIZE - cbDebugStringOffset - 1,
                        ", lpszStructType: %s", pszStructType);
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

void FormatObjectDebugExitA(_In_z_ const PCSTR pszFuncName,
                            _In_ const BOOL bStatus) {
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

_Success_(return != FALSE)
BOOL ConvertGuidToStringW(_In_ const GUID* pGuid,
                          _Outptr_result_z_ PWSTR* ppwszGuid) {
    const DWORD cchGuid = cchGUID_SIZE + 1; // Add terminating null

    *ppwszGuid = calloc(cchGuid, sizeof(WCHAR));
    if (*ppwszGuid == NULL) {
        DBG_PRINT("calloc() failed to allocate WCHAR array for GUID (errno: %d)\n", errno);
        return FALSE;
    }

    if (swprintf_s(*ppwszGuid,
                   cchGuid,
                   L"%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                   pGuid->Data1, pGuid->Data2, pGuid->Data3,
                   pGuid->Data4[0], pGuid->Data4[1], pGuid->Data4[2], pGuid->Data4[3],
                   pGuid->Data4[4], pGuid->Data4[5], pGuid->Data4[6], pGuid->Data4[7]) != -1) {
        return TRUE;
    }

    DBG_PRINT("swprintf_s() failed formatting GUID (errno: %d)\n", errno);

    free(*ppwszGuid);
    *ppwszGuid = NULL;

    return FALSE;
}

_Success_(return != FALSE)
BOOL DecodeAsnGuid(_In_reads_bytes_(cbEncoded) const BYTE* pbEncoded,
                   _In_ const DWORD cbEncoded,
                   _Outptr_ GUID** ppGuid) {
    BOOL bStatus = FALSE;
    CRYPT_INTEGER_BLOB* pbAsnGuidBlob = NULL;
    DWORD cbAsnGuidBlob = 0;

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING,
                             X509_OCTET_STRING,
                             pbEncoded,
                             cbEncoded,
                             CRYPT_DECODE_ALLOC_FLAG,
                             NULL,           // Use LocalAlloc()
                             &pbAsnGuidBlob, // NOLINT(bugprone-multi-level-implicit-pointer-conversion)
                             &cbAsnGuidBlob)) {
        DBG_PRINT("CryptDecodeObjectEx() of X509_OCTET_STRING failed (err: %u)\n", GetLastError());
        return bStatus;
    }

    if (pbAsnGuidBlob->cbData != sizeof(GUID)) {
        DBG_PRINT("Decoded ASN.1 octet string is %u bytes but expected %zu bytes\n",
                  pbAsnGuidBlob->cbData, sizeof(GUID));
        goto end;
    }

    *ppGuid = malloc(sizeof(GUID));
    if (*ppGuid == NULL) {
        DBG_PRINT("malloc() failed to allocate %zu bytes (errno: %d)\n", sizeof(GUID), errno);
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

_Success_(return != FALSE)
BOOL DecodeAsnSidA(_In_reads_bytes_(cbEncoded) const BYTE* pbEncoded,
                   _In_ const DWORD cbEncoded,
                   _Outptr_result_bytebuffer_(*cbSid) PSTR* ppszSid,
                   _Out_ DWORD* cbSid) {
    BOOL bStatus = FALSE;
    CRYPT_INTEGER_BLOB* pbAsnSidBlob = NULL;
    DWORD cbAsnSidBlob = 0;
    DWORD cbSidA;

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING,
                             X509_OCTET_STRING,
                             pbEncoded,
                             cbEncoded,
                             CRYPT_DECODE_ALLOC_FLAG,
                             NULL,          // Use LocalAlloc()
                             &pbAsnSidBlob, // NOLINT(bugprone-multi-level-implicit-pointer-conversion)
                             &cbAsnSidBlob)) {
        DBG_PRINT("CryptDecodeObjectEx() of X509_OCTET_STRING failed (err: %u)\n", GetLastError());
        return bStatus;
    }

    cbSidA = pbAsnSidBlob->cbData + sizeof(CHAR); // Add terminating null
    *ppszSid = calloc(cbSidA, sizeof(CHAR));
    if (*ppszSid == NULL) {
        DBG_PRINT("calloc() failed to allocate CHAR array for SID (errno: %d)\n", errno);
        goto end;
    }

    if (strncpy_s(*ppszSid, cbSidA, (CHAR*)pbAsnSidBlob->pbData, pbAsnSidBlob->cbData) != 0) {
        DBG_PRINT("strncpy_s() failed copying decoded SID bytes (errno: %d)\n", errno);
        free(*ppszSid);
        *ppszSid = NULL;
        goto end;
    }

    *cbSid = cbSidA;
    bStatus = TRUE;

end:
    LocalFree(pbAsnSidBlob);

    return bStatus;
}

BOOL FormatAsGuidStringW(_In_ const DWORD dwFormatStrType,
                         _In_reads_bytes_(cbEncoded) const BYTE* pbEncoded,
                         _In_ const DWORD cbEncoded,
                         _At_((WCHAR *)pbFormat, _Out_writes_bytes_(*pcbFormat)) void* pbFormat,
                         _Inout_ DWORD* pcbFormat) {
    BOOL bStatus = FALSE;
    GUID* pGuid = NULL;
    PWSTR pwszGuid = NULL;

    // Add newline & terminating null
    const DWORD cbBufferSize = (cchGUID_SIZE + 2) * sizeof(WCHAR);

    if (SetFormatBufferSize(pbFormat, pcbFormat, cbBufferSize)) {
        return TRUE;
    }

    if (!VerifyFormatBufferSize(*pcbFormat, cbBufferSize)) {
        return FALSE;
    }

    if (!DecodeAsnGuid(pbEncoded, cbEncoded, &pGuid)) {
        goto end;
    }

    if (!ConvertGuidToStringW(pGuid, &pwszGuid)) {
        goto end;
    }

    if (swprintf_s(pbFormat, *pcbFormat / sizeof(WCHAR), L"%s\n", pwszGuid) == -1) {
        DBG_PRINT("swprintf_s() failed formatting GUID to format buffer (errno: %d)\n", errno);
        goto end;
    }

    bStatus = TRUE;

end:
    free(pwszGuid);
    free(pGuid);

    return bStatus ? TRUE : SetFailureInfo(dwFormatStrType, pbFormat, *pcbFormat);
}

/*
 * The exported functions matching the CryptFormatObject() prototype can be
 * called with dwFormatStrType having CRYPT_FORMAT_STR_MULTI_LINE set. When not
 * set, this typically means the output is being formatted for a value field in
 * a list view. If so, it's generally better to return a failure message as the
 * output, otherwise the field will simply be blank.
 */
BOOL SetFailureInfo(_In_ const DWORD dwFormatStrType,
                    _At_((WCHAR *)pbFormat, _Out_writes_bytes_(cbFormat)) void* pbFormat,
                    _In_ const DWORD cbFormat) {
    if (dwFormatStrType == CRYPT_FORMAT_STR_SINGLE_LINE) {
        if (cbFormat >= sizeof(wszFORMAT_FAILURE)) {
            if (wcscpy_s(pbFormat, cbFormat / sizeof(WCHAR), wszFORMAT_FAILURE) == 0) {
                return TRUE;
            }

            DBG_PRINT("wcscpy_s() failed copying string to format buffer (errno: %d)\n", errno);
            return FALSE;
        }

        DBG_PRINT("Format function failed and format buffer of %u bytes insufficient for failure string\n", cbFormat);
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
_Success_(return != FALSE)
BOOL SetFormatBufferSize(_Out_opt_ const void* pbFormat,
                         _Inout_ DWORD* pcbFormat,
                         _In_ const DWORD cbSize) {
    if (pbFormat != NULL || *pcbFormat != 0) {
        return FALSE;
    }

    *pcbFormat = cbSize;
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
BOOL VerifyFormatBufferSize(_In_ const DWORD cbFormat,
                            _In_ const DWORD cbSize) {
    if (cbFormat >= cbSize) {
        return TRUE;
    }

    DBG_PRINT("Output buffer is %u bytes but must be at least %u bytes\n", cbFormat, cbSize);
    SetLastError(ERROR_MORE_DATA);
    return FALSE;
}
