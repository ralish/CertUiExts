#include "pch.h"

#include <wincrypt.h>

/*
 * NTDS-DSA Invocation ID
 * 1.2.840.113556.1.5.284.1
 *
 * [MS-DVRE]: Device Registration Enrollment Protocol
 * Section 3.1.4.2.1: New Request Processing
 *
 * [MS-DVRJ]: Device Registration Join Protocol
 * Section 3.1.5.1.1.3: Processing Details
 */
__declspec(dllexport)
BOOL FormatEntraIdNtdsDsaInvId(_In_ const DWORD dwCertEncodingType,
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
 * Device ID
 * 1.2.840.113556.1.5.284.2
 *
 * Refer to comments for OID: 1.2.840.113556.1.5.284.1
 */
__declspec(dllexport)
BOOL FormatEntraIdDeviceId(_In_ const DWORD dwCertEncodingType,
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
 * 1.2.840.113556.1.5.284.3
 *
 * Refer to comments for OID: 1.2.840.113556.1.5.284.1
 */
__declspec(dllexport)
BOOL FormatEntraIdUserId(_In_ const DWORD dwCertEncodingType,
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
 * Domain ID
 * 1.2.840.113556.1.5.284.4
 *
 * Refer to comments for OID: 1.2.840.113556.1.5.284.1
 */
__declspec(dllexport)
BOOL FormatEntraIdDomainId(_In_ const DWORD dwCertEncodingType,
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
 * Tenant ID
 * 1.2.840.113556.1.5.284.5
 *
 * Undocumented
 */
__declspec(dllexport)
BOOL FormatEntraIdTenantId(_In_ const DWORD dwCertEncodingType,
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
 * Join Type
 * 1.2.840.113556.1.5.284.7
 *
 * Undocumented
 */
__declspec(dllexport)
BOOL FormatEntraIdJoinType(_In_ const DWORD dwCertEncodingType,
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

    // Join type
    CRYPT_INTEGER_BLOB* pbAadJoinTypeBlob = NULL;
    DWORD cbAadJoinTypeBlob = 0;
    WCHAR* pwszJoinType;

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING,
                             X509_OCTET_STRING,
                             pbEncoded,
                             cbEncoded,
                             CRYPT_DECODE_ALLOC_FLAG,
                             NULL,               // Use LocalAlloc()
                             &pbAadJoinTypeBlob, // NOLINT(bugprone-multi-level-implicit-pointer-conversion)
                             &cbAadJoinTypeBlob)) {
        DBG_PRINT("CryptDecodeObjectEx() of X509_OCTET_STRING failed (err: %u)\n", GetLastError());
        goto end;
    }

    if (pbAadJoinTypeBlob->cbData != 1) {
        DBG_PRINT("ASN.1 octet string is %u bytes but expected 1 byte\n", pbAadJoinTypeBlob->cbData);
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

    if (swprintf_s((WCHAR*)pbFormat, *pcbFormat / sizeof(WCHAR), L"%s\n", pwszJoinType) == -1) {
        DBG_PRINT("swprintf_s() failed formatting string to format buffer (errno: %d)\n", errno);
        goto end;
    }

    bStatus = TRUE;

end:
    LocalFree(pbAadJoinTypeBlob);

    DBG_EXIT(bStatus);
    return bStatus ? TRUE : SetFailureInfo(dwFormatStrType, pbFormat, *pcbFormat);
}

/*
 * Tenant Region
 * 1.2.840.113556.1.5.284.8
 *
 * Undocumented
 */
__declspec(dllexport)
BOOL FormatEntraIdTenantRegion(_In_ const DWORD dwCertEncodingType,
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

    // Tenant region
    CRYPT_INTEGER_BLOB* pbAadTenantRegionBlob = NULL;
    DWORD cbAadTenantRegionBlob = 0;
    WCHAR* pwszTenantRegionName;
    WCHAR wszTenantRegionCode[3];
    size_t cchTenantRegionCode;

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING,
                             X509_OCTET_STRING,
                             pbEncoded,
                             cbEncoded,
                             CRYPT_DECODE_ALLOC_FLAG,
                             NULL,                   // Use LocalAlloc()
                             &pbAadTenantRegionBlob, // NOLINT(bugprone-multi-level-implicit-pointer-conversion)
                             &cbAadTenantRegionBlob)) {
        DBG_PRINT("CryptDecodeObjectEx() of X509_OCTET_STRING failed (err: %u)\n", GetLastError());
        goto end;
    }

    if (pbAadTenantRegionBlob->cbData != 2) {
        DBG_PRINT("ASN.1 octet string is %u bytes but expected 2 bytes\n", pbAadTenantRegionBlob->cbData);
        goto end;
    }

    if (mbstowcs_s(&cchTenantRegionCode, wszTenantRegionCode, sizeof(wszTenantRegionCode) / sizeof(WCHAR),
                   (CHAR*)pbAadTenantRegionBlob->pbData, pbAadTenantRegionBlob->cbData) != 0) {
        DBG_PRINT("mbstowcs_s() failed converting tenant region code (errno: %d)\n", errno);
        goto end;
    }

    // Check buffer size is adequate if modifying cases
    if (wcscmp(wszTenantRegionCode, L"AF") == 0) {
        pwszTenantRegionName = L"Africa";
    } else if (wcscmp(wszTenantRegionCode, L"AP") == 0) {
        pwszTenantRegionName = L"Asia-Pacific";
    } else if (wcscmp(wszTenantRegionCode, L"AS") == 0) {
        pwszTenantRegionName = L"Asia";
    } else if (wcscmp(wszTenantRegionCode, L"EU") == 0) {
        pwszTenantRegionName = L"Europe";
    } else if (wcscmp(wszTenantRegionCode, L"ME") == 0) {
        pwszTenantRegionName = L"Middle East";
    } else if (wcscmp(wszTenantRegionCode, L"NA") == 0) {
        pwszTenantRegionName = L"North America";
    } else if (wcscmp(wszTenantRegionCode, L"OC") == 0) {
        pwszTenantRegionName = L"Oceania";
    } else if (wcscmp(wszTenantRegionCode, L"SA") == 0) {
        pwszTenantRegionName = L"South America";
    } else {
        pwszTenantRegionName = L"Unknown";
    }

    if (swprintf_s((WCHAR*)pbFormat, *pcbFormat / sizeof(WCHAR),
                   L"%s (%s)\n", pwszTenantRegionName, wszTenantRegionCode) == -1) {
        DBG_PRINT("swprintf_s() failed formatting string to format buffer (errno: %d)\n", errno);
        goto end;
    }

    bStatus = TRUE;

end:
    LocalFree(pbAadTenantRegionBlob);

    DBG_EXIT(bStatus);
    return bStatus ? TRUE : SetFailureInfo(dwFormatStrType, pbFormat, *pcbFormat);
}
