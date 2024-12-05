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
                                  _In_z_ const LPCSTR lpszStructType,
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
    BYTE bVersion;
    WCHAR* pwszPrefix;

    switch (cbEncoded) {
        // Empty is version zero
        case 0:
            bVersion = 0;
            break;
        // Single byte with version
        case 1:
            bVersion = pbEncoded[0];
            break;
        default:
            DBG_PRINT("Extension is %u bytes but expected 1 byte\n", cbEncoded);
            goto end;
    }

    pwszPrefix = dwFormatStrType == CRYPT_FORMAT_STR_SINGLE_LINE ? L"V" : L"Version ";
    if (swprintf_s(pbFormat, *pcbFormat / sizeof(WCHAR), L"%s%u\n", pwszPrefix, bVersion) == -1) {
        DBG_PRINT("swprintf_s() failed formatting string to format buffer (errno: %d)\n", errno);
        goto end;
    }

    bStatus = TRUE;

end:
    DBG_EXIT(bStatus);
    return bStatus ? TRUE : SetFailureInfo(dwFormatStrType, pbFormat, *pcbFormat);
}
