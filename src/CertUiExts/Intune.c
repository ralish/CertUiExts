#include "pch.h"

#include <stdlib.h>
#include <malloc.h>

#include "CertUiExts.h"

/*
 * Device ID
 * 1.2.840.113556.5.4
 *
 * This extension is a little unusual as the GUID isn't encoded, unlike all the
 * others. Instead, the raw GUID bytes are there with no ASN.1 tag or length.
 */
__declspec(dllexport)
BOOL FormatIntuneDeviceId(_In_ DWORD dwCertEncodingType,
                          _In_ DWORD dwFormatType,
                          _In_ DWORD dwFormatStrType,
                          _In_opt_ void* pFormatStruct,
                          _In_opt_ LPCSTR lpszStructType,
                          _In_reads_bytes_(cbEncoded) const BYTE* pbEncoded,
                          _In_ DWORD cbEncoded,
                          _At_((WCHAR *)pbFormat, _Out_writes_bytes_to_opt_(*pcbFormat, *pcbFormat)) void* pbFormat,
                          _Inout_ DWORD* pcbFormat)
{
    BOOL   bStatus = FALSE;
    GUID*  pGuid = NULL;
    LPWSTR pwszGuid = NULL;

    DBG_ENTER(dwCertEncodingType, dwFormatStrType, lpszStructType, *pcbFormat);

    if (SetFormatBufferSize(pbFormat, pcbFormat, cbGUID_SIZE_W)) {
        SetLastError(ERROR_MORE_DATA);
        return TRUE;
    }

    if (*pcbFormat < cbGUID_SIZE_W) {
        DBG_PRINT("Output buffer must be at least %u bytes but is %u bytes\n", cbGUID_SIZE_W, *pcbFormat);
        *pcbFormat = cbGUID_SIZE_W;
        SetLastError(ERROR_MORE_DATA);
        goto end;
    }

    if (cbEncoded != sizeof(GUID)) {
        DBG_PRINT("Extension has %u bytes but expected %u bytes\n", cbEncoded, (DWORD)sizeof(GUID));
        goto end;
    }

    pGuid = malloc(sizeof(GUID));
    if (pGuid == NULL) {
        DBG_PRINT("malloc() failed to allocate %u bytes (errno: %d)\n", (DWORD)sizeof(GUID), errno);
        goto end;
    }

    if (memcpy_s(pGuid, sizeof(GUID), pbEncoded, cbEncoded) != 0) {
        DBG_PRINT("memcpy_s() failed copying GUID bytes (errno: %d)\n", errno);
        goto end;
    }

    if (!ConvertGuidToStringW(pGuid, &pwszGuid)) {
        goto end;
    }

    if (wcscpy_s(pbFormat, *pcbFormat / sizeof(WCHAR), pwszGuid) != 0) {
        DBG_PRINT("wcscpy_s() failed copying string to output buffer (errno: %d)\n", errno);
        goto end;
    }

    bStatus = TRUE;

end:
    free(pwszGuid);
    free(pGuid);

    return bStatus ? TRUE : SetFailureInfo(dwFormatStrType, pbFormat, pcbFormat);
}

/*
 * Account ID
 * 1.2.840.113556.5.6
 */
__declspec(dllexport)
BOOL FormatIntuneAccountId(_In_ DWORD dwCertEncodingType,
                           _In_ DWORD dwFormatType,
                           _In_ DWORD dwFormatStrType,
                           _In_opt_ void* pFormatStruct,
                           _In_opt_ LPCSTR lpszStructType,
                           _In_reads_bytes_(cbEncoded) const BYTE* pbEncoded,
                           _In_ DWORD cbEncoded,
                           _At_((WCHAR *)pbFormat, _Out_writes_bytes_to_opt_(*pcbFormat, *pcbFormat)) void* pbFormat,
                           _Inout_ DWORD* pcbFormat)
{
    BOOL bStatus;

    DBG_ENTER(dwCertEncodingType, dwFormatStrType, lpszStructType, *pcbFormat);
    bStatus = FormatAsGuidStringW(dwFormatStrType, pbEncoded, cbEncoded, pbFormat, pcbFormat);
    DBG_EXIT(bStatus);

    return bStatus;
}

#ifdef _DEBUG
/*
 * Unknown
 * 1.2.840.113556.5.11
 */
__declspec(dllexport)
BOOL FormatIntuneUnknown11(_In_ DWORD dwCertEncodingType,
                           _In_ DWORD dwFormatType,
                           _In_ DWORD dwFormatStrType,
                           _In_opt_ void* pFormatStruct,
                           _In_opt_ LPCSTR lpszStructType,
                           _In_reads_bytes_(cbEncoded) const BYTE* pbEncoded,
                           _In_ DWORD cbEncoded,
                           _At_((WCHAR *)pbFormat, _Out_writes_bytes_to_opt_(*pcbFormat, *pcbFormat)) void* pbFormat,
                           _Inout_ DWORD* pcbFormat)
{
    BOOL bStatus;

    DBG_ENTER(dwCertEncodingType, dwFormatStrType, lpszStructType, *pcbFormat);
    bStatus = FormatAsGuidStringW(dwFormatStrType, pbEncoded, cbEncoded, pbFormat, pcbFormat);
    DBG_EXIT(bStatus);

    return bStatus;
}
#endif

/*
 * Tenant ID
 * 1.2.840.113556.5.14
 */
__declspec(dllexport)
BOOL FormatIntuneAadTenantId(_In_ DWORD dwCertEncodingType,
                             _In_ DWORD dwFormatType,
                             _In_ DWORD dwFormatStrType,
                             _In_opt_ void* pFormatStruct,
                             _In_opt_ LPCSTR lpszStructType,
                             _In_reads_bytes_(cbEncoded) const BYTE* pbEncoded,
                             _In_ DWORD cbEncoded,
                             _At_((WCHAR *)pbFormat, _Out_writes_bytes_to_opt_(*pcbFormat, *pcbFormat)) void* pbFormat,
                             _Inout_ DWORD* pcbFormat)
{
    BOOL bStatus;

    DBG_ENTER(dwCertEncodingType, dwFormatStrType, lpszStructType, *pcbFormat);
    bStatus = FormatAsGuidStringW(dwFormatStrType, pbEncoded, cbEncoded, pbFormat, pcbFormat);
    DBG_EXIT(bStatus);

    return bStatus;
}
