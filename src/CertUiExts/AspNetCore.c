#include "pch.h"

/*
 * HTTPS Development Certificate
 * 1.3.6.1.4.1.311.84.1.1
 *
 * Undocumented but open-source:
 * https://github.com/dotnet/aspnetcore/blob/main/src/Shared/CertificateGeneration/CertificateManager.cs
 */
__declspec(dllexport)
BOOL FormatAspNetCoreHttpsDevCert(_In_ const DWORD dwCertEncodingType,
                                  _In_ const DWORD dwFormatType,
                                  _In_ const DWORD dwFormatStrType,
                                  _In_opt_ const void* pFormatStruct,
                                  _In_opt_ const LPCSTR lpszStructType,
                                  _In_reads_bytes_(cbEncoded) const BYTE* pbEncoded,
                                  _In_ const DWORD cbEncoded,
                                  _At_((WCHAR *)pbFormat, _Out_writes_bytes_to_opt_(*pcbFormat, *pcbFormat)) void* pbFormat,
                                  _Inout_ DWORD* pcbFormat) {
    UNREFERENCED_PARAMETER(dwCertEncodingType);
    UNREFERENCED_PARAMETER(dwFormatType);
    UNREFERENCED_PARAMETER(pFormatStruct);
    UNREFERENCED_PARAMETER(lpszStructType);

    DBG_ENTER(dwCertEncodingType, dwFormatStrType, lpszStructType, *pcbFormat);

    if (SetFormatBufferSize(pbFormat, pcbFormat, cbFORMAT_MIN_SIZE)) {
        return TRUE;
    }

    if (!VerifyFormatBufferSize(*pcbFormat, cbFORMAT_MIN_SIZE)) {
        return FALSE;
    }

    BOOL bStatus = FALSE;

    // Version
    INT iVersion;
    WCHAR wszVersion[4]; // Largest single byte integer

    switch (cbEncoded) {
        // Empty is version zero
        case 0:
            iVersion = 0;
            break;
        // Single byte with version
        case 1:
            iVersion = pbEncoded[0];
            break;
        default:
            DBG_PRINT("Extension is %u bytes but expected 1 byte\n", cbEncoded);
            goto end;
    }

    if (_itow_s(iVersion, wszVersion, sizeof(wszVersion) / sizeof(WCHAR), 10) != 0) {
        DBG_PRINT("_itow_s() failed converting integer to string (errno: %d)\n", errno);
        goto end;
    }

    if (dwFormatStrType == CRYPT_FORMAT_STR_SINGLE_LINE) {
        if (wcscpy_s(pbFormat, *pcbFormat / sizeof(WCHAR), wszVersion) == 0) {
            bStatus = TRUE;
        } else {
            DBG_PRINT("wcscpy_s() failed copying string to format buffer (errno: %d)\n", errno);
        }

        goto end;
    }

    if (swprintf_s(pbFormat, *pcbFormat / sizeof(WCHAR), L"Version %d\n", iVersion) == -1) {
        DBG_PRINT("swprintf_s() failed formatting string to format buffer (errno: %d)\n", errno);
        goto end;
    }

    bStatus = TRUE;

end:
    DBG_EXIT(bStatus);
    return bStatus ? TRUE : SetFailureInfo(dwFormatStrType, pbFormat, *pcbFormat);
}
