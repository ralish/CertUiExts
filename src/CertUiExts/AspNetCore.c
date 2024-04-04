#include "pch.h"

#include <stdlib.h>
#include <stdio.h>

#include "Shared.h"

#include "CertUiExts.h"
#include "OIDs.h"

/*
 * HTTPS Development Certificate
 * 1.3.6.1.4.1.311.84.1.1
 *
 * This extension should contain a single byte which represents the certificate
 * version, or be empty, which is equivalent to setting the version to zero.
 */
__declspec(dllexport)
BOOL FormatAspNetCoreHttpsDevCert(_In_ const DWORD dwCertEncodingType,
                                  _In_ const DWORD dwFormatType,
                                  _In_ const DWORD dwFormatStrType,
                                  _In_opt_ const void* pFormatStruct,
                                  _In_opt_ const LPCSTR lpszStructType,
                                  _In_reads_bytes_(cbEncoded) const BYTE* pbEncoded,
                                  _In_ const DWORD cbEncoded,
                                  _At_((WCHAR *)pbFormat, _Out_writes_bytes_to_opt_(*pcbFormat, *pcbFormat)) void*
                                  pbFormat,
                                  _Inout_ DWORD* pcbFormat) {
    UNREFERENCED_PARAMETER(dwFormatType);
    UNREFERENCED_PARAMETER(pFormatStruct);

    BOOL bStatus = FALSE;
    INT dwVersion = 0;
    WCHAR pszVersion[4]; // Largest integer for a single byte is 254

    DBG_ENTER(dwCertEncodingType, dwFormatStrType, lpszStructType, *pcbFormat);

    if (SetFormatBufferSize(pbFormat, pcbFormat, cbASPNETCORE_HTTPS_DEV_CERT_BUFFER)) {
        return TRUE;
    }

    if (!VerifyFormatBufferSize(pcbFormat, cbASPNETCORE_HTTPS_DEV_CERT_BUFFER)) {
        return FALSE;
    }

    switch (cbEncoded) {
        case 0:
            break;
        case 1:
            dwVersion = pbEncoded[0];
            break;
        default:
            DBG_PRINT("Extension has %u bytes but expected 1 byte\n", cbEncoded);
            goto end;
    }

    if (_itow_s(dwVersion, pszVersion, 4, 10) != 0) {
        DBG_PRINT("_itow_s() failed to convert integer to a string (errno: %d)\n", errno);
        goto end;
    }

    // Single line display
    if (dwFormatStrType == 0) {
        if (wcscpy_s(pbFormat, *pcbFormat / sizeof(WCHAR), pszVersion) == 0) {
            bStatus = TRUE;
            goto end;
        }

        DBG_PRINT("wcscpy_s() failed copying string to output buffer (errno: %d)\n", errno);
        goto end;
    }

    if (swprintf_s(pbFormat, *pcbFormat / sizeof(WCHAR), L"Version %u\n", dwVersion) == -1) {
        DBG_PRINT("swprintf_s() failed to format string to output buffer (errno: %d)\n", errno);
        goto end;
    }

    bStatus = TRUE;

end:
    return bStatus ? TRUE : SetFailureInfo(dwFormatStrType, pbFormat, pcbFormat);
}
