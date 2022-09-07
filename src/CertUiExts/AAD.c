#include "pch.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <wincrypt.h>

#include "CertUiExts.h"
#include "OIDs.h"

/*
 * NTDS-DSA Invocation ID
 * 1.2.840.113556.1.5.284.1
 */
__declspec(dllexport)
BOOL FormatAadNtdsDsaIid(_In_ DWORD dwCertEncodingType,
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

/*
 * Device ID
 * 1.2.840.113556.1.5.284.2
 */
__declspec(dllexport)
BOOL FormatAadDeviceId(_In_ DWORD dwCertEncodingType,
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

/*
 * User ID
 * 1.2.840.113556.1.5.284.3
 */
__declspec(dllexport)
BOOL FormatAadUserId(_In_ DWORD dwCertEncodingType,
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

/*
 * Domain ID
 * 1.2.840.113556.1.5.284.4
 */
__declspec(dllexport)
BOOL FormatAadDomainId(_In_ DWORD dwCertEncodingType,
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

/*
 * Tenant ID
 * 1.2.840.113556.1.5.284.5
 */
__declspec(dllexport)
BOOL FormatAadTenantId(_In_ DWORD dwCertEncodingType,
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

/*
 * Join Type
 * 1.2.840.113556.1.5.284.7
 */
__declspec(dllexport)
BOOL FormatAadJoinType(_In_ DWORD dwCertEncodingType,
                       _In_ DWORD dwFormatType,
                       _In_ DWORD dwFormatStrType,
                       _In_opt_ void* pFormatStruct,
                       _In_opt_ LPCSTR lpszStructType,
                       _In_reads_bytes_(cbEncoded) const BYTE* pbEncoded,
                       _In_ DWORD cbEncoded,
                       _At_((WCHAR *)pbFormat, _Out_writes_bytes_to_opt_(*pcbFormat, *pcbFormat)) void* pbFormat,
                       _Inout_ DWORD* pcbFormat)
{
    BOOL                bStatus = FALSE;
    CRYPT_INTEGER_BLOB* pbAadJoinTypeBlob = NULL;
    DWORD               cbAadJoinTypeBlob = 0;
    WCHAR*              pwszJoinType;

    DBG_ENTER(dwCertEncodingType, dwFormatStrType, lpszStructType, *pcbFormat);

    if (SetFormatBufferSize(pbFormat, pcbFormat, cbAAD_JOIN_TYPE_BUFFER)) {
        SetLastError(ERROR_MORE_DATA);
        return TRUE;
    }

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING,
                             X509_OCTET_STRING,
                             pbEncoded,
                             cbEncoded,
                             CRYPT_DECODE_ALLOC_FLAG,
                             NULL, // Use LocalAlloc()
                             &pbAadJoinTypeBlob,
                             &cbAadJoinTypeBlob)) {
        DBG_PRINT("CryptDecodeObjectEx() failed (err: %u)\n", GetLastError());
        return bStatus;
    }

    if (pbAadJoinTypeBlob->cbData != 1) {
        DBG_PRINT("Decoded ASN.1 octet string has %u bytes but expected 1 bytes\n", pbAadJoinTypeBlob->cbData);
        goto end;
    }

    // Check buffer size is adequate if modifying cases
    switch ((CHAR)pbAadJoinTypeBlob->pbData[0]) {
        case '0':
            pwszJoinType = L"Registered (0)";
            break;
        case '1':
            pwszJoinType = L"Joined (1)";
            break;
        default:
            goto end;
    }

    if  (swprintf_s(pbFormat, *pcbFormat / sizeof(WCHAR), L"%s\n", pwszJoinType) == -1) {
        DBG_PRINT("swprintf_s() failed to format string to output buffer (errno: %d)\n", errno);
        goto end;
    }

    bStatus = TRUE;

end:
    LocalFree(pbAadJoinTypeBlob);

    DBG_EXIT(bStatus);
    return bStatus ? TRUE : SetFailureInfo(dwFormatStrType, pbFormat, pcbFormat);
}

/*
 * Tenant Region
 * 1.2.840.113556.1.5.284.8
 */
__declspec(dllexport)
BOOL FormatAadTenantRegion(_In_ DWORD dwCertEncodingType,
                           _In_ DWORD dwFormatType,
                           _In_ DWORD dwFormatStrType,
                           _In_opt_ void* pFormatStruct,
                           _In_opt_ LPCSTR lpszStructType,
                           _In_reads_bytes_(cbEncoded) const BYTE* pbEncoded,
                           _In_ DWORD cbEncoded,
                           _At_((WCHAR *)pbFormat, _Out_writes_bytes_to_opt_(*pcbFormat, *pcbFormat)) void* pbFormat,
                           _Inout_ DWORD* pcbFormat)
{
    BOOL                bStatus = FALSE;
    CRYPT_INTEGER_BLOB* pbAadTenantRegionBlob = NULL;
    DWORD               cbAadTenantRegionBlob = 0;
    WCHAR*              pwszTenantRegionName;
    WCHAR               pwszTenantRegionCode[3];
    size_t              ccTenantRegionCode;

    DBG_ENTER(dwCertEncodingType, dwFormatStrType, lpszStructType, *pcbFormat);

    if (SetFormatBufferSize(pbFormat, pcbFormat, cbAAD_TENANT_REGION_BUFFER)) {
        SetLastError(ERROR_MORE_DATA);
        return TRUE;
    }

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING,
                             X509_OCTET_STRING,
                             pbEncoded,
                             cbEncoded,
                             CRYPT_DECODE_ALLOC_FLAG,
                             NULL, // Use LocalAlloc()
                             &pbAadTenantRegionBlob,
                             &cbAadTenantRegionBlob)) {
        DBG_PRINT("CryptDecodeObjectEx() failed (err: %u)\n", GetLastError());
        return bStatus;
    }

    if (pbAadTenantRegionBlob->cbData != 2) {
        DBG_PRINT("Decoded ASN.1 octet string has %u bytes but expected 2 bytes\n", pbAadTenantRegionBlob->cbData);
        goto end;
    }

    if (mbstowcs_s(&ccTenantRegionCode,
                   pwszTenantRegionCode, sizeof(pwszTenantRegionCode) / sizeof(WCHAR),
                   (CHAR*)pbAadTenantRegionBlob->pbData, pbAadTenantRegionBlob->cbData) != 0) {
        DBG_PRINT("mbstowcs_s() failed converting tenant region code (errno: %d)\n", errno);
        goto end;
    }

    // Check buffer size is adequate if modifying cases
    if (wcscmp(pwszTenantRegionCode, L"AF") == 0) {
        pwszTenantRegionName = L"Africa";
    } else if (wcscmp(pwszTenantRegionCode, L"AP") == 0) {
        pwszTenantRegionName = L"Asia-Pacific";
    } else if (wcscmp(pwszTenantRegionCode, L"AS") == 0) {
        pwszTenantRegionName = L"Asia";
    } else if (wcscmp(pwszTenantRegionCode, L"EU") == 0) {
        pwszTenantRegionName = L"Europe";
    } else if (wcscmp(pwszTenantRegionCode, L"ME") == 0) {
        pwszTenantRegionName = L"Middle East";
    } else if (wcscmp(pwszTenantRegionCode, L"NA") == 0) {
        pwszTenantRegionName = L"North America";
    } else if (wcscmp(pwszTenantRegionCode, L"OC") == 0) {
        pwszTenantRegionName = L"Oceania";
    } else if (wcscmp(pwszTenantRegionCode, L"SA") == 0) {
        pwszTenantRegionName = L"South America";
    } else {
        pwszTenantRegionName = L"Unknown";
    }

    if (swprintf_s(pbFormat, *pcbFormat / sizeof(WCHAR), L"%s (%s)\n", pwszTenantRegionName, pwszTenantRegionCode) == -1) {
        DBG_PRINT("swprintf_s() failed to format string to output buffer (errno: %d)\n", errno);
        goto end;
    }

    bStatus = TRUE;

end:
    LocalFree(pbAadTenantRegionBlob);

    DBG_EXIT(bStatus);
    return bStatus ? TRUE : SetFailureInfo(dwFormatStrType, pbFormat, pcbFormat);
}
