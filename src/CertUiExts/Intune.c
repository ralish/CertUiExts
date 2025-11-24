#include "pch.h"

/*
 * FUTURE
 *
 * 1.2.840.113556.5.3
 * Found in certca.dll, CertEnroll.dll, CertEnrollUI.dll
 *
 * 1.2.840.113556.5.10
 * Found in certca.dll, CertEnroll.dll, CertEnrollUI.dll
 */

/*
 * Device ID
 * 1.2.840.113556.5.4
 *
 * Undocumented
 *
 * This extension is a little unusual as the GUID isn't encoded, unlike all the
 * others. Instead, the raw GUID bytes are there with no ASN.1 tag or length.
 */
__declspec(dllexport)
BOOL FormatIntuneDeviceId(_In_ const DWORD dwCertEncodingType,
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

    // Add newline & terminating null
    const DWORD cbBufferSize = (cchGUID_SIZE + 2) * sizeof(WCHAR);

    if (SetFormatBufferSize(pbFormat, pcbFormat, cbBufferSize)) {
        return TRUE;
    }

    if (!VerifyFormatBufferSize(*pcbFormat, cbBufferSize)) {
        return FALSE;
    }

    BOOL bStatus = FALSE;

    // GUID
    GUID* pGuid = NULL;
    PWSTR pwszGuid = NULL;

    if (cbEncoded != sizeof(GUID)) {
        DBG_PRINT("Extension is %u bytes but expected %zu bytes\n", cbEncoded, sizeof(GUID));
        goto end;
    }

    pGuid = (GUID*)malloc(sizeof(GUID));
    if (pGuid == NULL) {
        DBG_PRINT("malloc() failed to allocate %zu bytes (errno: %d)\n", sizeof(GUID), errno);
        goto end;
    }

    if (memcpy_s(pGuid, sizeof(GUID), pbEncoded, cbEncoded) != 0) {
        DBG_PRINT("memcpy_s() failed copying GUID bytes (errno: %d)\n", errno);
        goto end;
    }

    if (!ConvertGuidToStringW(pGuid, &pwszGuid)) {
        goto end;
    }

    if (swprintf_s((WCHAR*)pbFormat, *pcbFormat / sizeof(WCHAR), L"%s\n", pwszGuid) == -1) {
        DBG_PRINT("swprintf_s() failed formatting string to format buffer (errno: %d)\n", errno);
        goto end;
    }

    bStatus = TRUE;

end:
    free(pwszGuid);
    free(pGuid);

    DBG_EXIT(bStatus);
    return bStatus ? TRUE : SetFailureInfo(dwFormatStrType, pbFormat, *pcbFormat);
}

/*
 * Account ID
 * 1.2.840.113556.5.6
 *
 * Undocumented
 */
__declspec(dllexport)
BOOL FormatIntuneAccountId(_In_ const DWORD dwCertEncodingType,
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

    BOOL bStatus;

    DBG_ENTER(dwCertEncodingType, dwFormatStrType, lpszStructType, *pcbFormat);
    bStatus = FormatAsGuidStringW(dwFormatStrType, pbEncoded, cbEncoded, pbFormat, pcbFormat);
    DBG_EXIT(bStatus);

    return bStatus;
}

/*
 * User ID
 * 1.2.840.113556.5.10
 *
 * Undocumented
 */
__declspec(dllexport)
BOOL FormatIntuneUserId(_In_ const DWORD dwCertEncodingType,
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
 *
 * Undocumented
 */
__declspec(dllexport)
BOOL FormatIntuneUnknown11(_In_ const DWORD dwCertEncodingType,
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

    BOOL bStatus;

    DBG_ENTER(dwCertEncodingType, dwFormatStrType, lpszStructType, *pcbFormat);
    bStatus = FormatAsGuidStringW(dwFormatStrType, pbEncoded, cbEncoded, pbFormat, pcbFormat);
    DBG_EXIT(bStatus);

    return bStatus;
}
#endif

/*
 * Entra ID Tenant ID
 * 1.2.840.113556.5.14
 *
 * Undocumented
 */
__declspec(dllexport)
BOOL FormatIntuneEntraIdTenantId(_In_ const DWORD dwCertEncodingType,
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

    BOOL bStatus;

    DBG_ENTER(dwCertEncodingType, dwFormatStrType, lpszStructType, *pcbFormat);
    bStatus = FormatAsGuidStringW(dwFormatStrType, pbEncoded, cbEncoded, pbFormat, pcbFormat);
    DBG_EXIT(bStatus);

    return bStatus;
}
