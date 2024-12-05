#include "pch.h"

#include <sddl.h>
#include <wincrypt.h>

#include "Asn1.h"
#include "Ntds.h"

/*
 * CA Security
 * 1.3.6.1.4.1.311.25.2
 *
 * [MS-WCCE]: Windows Client Certificate Enrollment Protocol
 * Section 2.2.2.7.7.4 szOID_NTDS_CA_SECURITY_EXT
 *
 * Certificate-based authentication changes on Windows domain controllers
 * https://support.microsoft.com/kb/5014754
 */
__declspec(dllexport)
BOOL FormatNtdsCaSecurityExt(_In_ const DWORD dwCertEncodingType,
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

    if (SetFormatBufferSize(pbFormat, pcbFormat, cbCA_SECURITY_EXT_BUFFER)) {
        return TRUE;
    }

    if (!VerifyFormatBufferSize(*pcbFormat, cbCA_SECURITY_EXT_BUFFER)) {
        return FALSE;
    }

    BOOL bStatus = FALSE;
    size_t cbByteOffset = 0;
    size_t cbAttrOffset;
    size_t cchNumChars;

    // Object identifier
    PSTR* ppszOid = NULL;
    PWSTR pwszOid = NULL;
    DWORD cbOidA = 0;

    // Security identifier
    PSTR pszSid = NULL;
    PWSTR pwszSid = NULL;
    DWORD cbSidA;

    // Account details
    PSID pSid = NULL;
    PWSTR pwszSidAccountName = NULL;
    DWORD cbSidAccountName = 0;
    PWSTR pwszSidAccountDomain = NULL;
    DWORD cbSidAccountDomain = 0;
    SID_NAME_USE sidType;
    DWORD dwLookupError;

    if (cbEncoded < cbCA_SECURITY_EXT_ASN_MIN) {
        DBG_PRINT("ASN.1 structure is %u bytes but expected at least %u bytes\n",
                  cbEncoded, cbCA_SECURITY_EXT_ASN_MIN);
        goto end;
    }

    // Sequence: Tag
    if (pbEncoded[cbByteOffset] != ASN_SEQUENCE) {
        DBG_PRINT("Expected a sequence tag but found: 0x%x\n",
                  pbEncoded[cbByteOffset]);
        goto end;
    }
    cbByteOffset++;

    // Sequence: Max length
    if (pbEncoded[cbByteOffset] > cbASN_LENGTH_SINGLE_BYTE_MAX) {
        DBG_PRINT("ASN.1 sequence is %u bytes but expected at most %u bytes\n",
                  pbEncoded[cbByteOffset], cbASN_LENGTH_SINGLE_BYTE_MAX);
        goto end;
    }

    // Sequence: Min length (minus type & length bytes)
    if (pbEncoded[cbByteOffset] < cbCA_SECURITY_EXT_ASN_MIN - 2) {
        DBG_PRINT("ASN.1 sequence is %u bytes but expected at least %u bytes\n",
                  pbEncoded[cbByteOffset], cbCA_SECURITY_EXT_ASN_MIN - 2);
        goto end;
    }

    // Sequence: Buffer size (minus type & length bytes)
    if (pbEncoded[cbByteOffset] > cbEncoded - 2) {
        DBG_PRINT("ASN.1 sequence is %u bytes but buffer has only %u bytes\n",
                  pbEncoded[cbByteOffset], cbEncoded - 2);
        goto end;
    }
    cbByteOffset++;
    cbAttrOffset = cbByteOffset;

    // OID context: Tag
    if (pbEncoded[cbByteOffset] != (ASN_CONTEXT | ASN_CONSTRUCTED)) {
        DBG_PRINT("Expected a context-specific constructed tag before OID but found: 0x%x\n",
                  pbEncoded[cbByteOffset]);
        goto end;
    }
    cbByteOffset++;

    // OID context: Max length
    if (pbEncoded[cbByteOffset] > cbASN_LENGTH_SINGLE_BYTE_MAX - cbAttrOffset) {
        DBG_PRINT("OID context is %u bytes but expected at most %zu bytes\n",
                  pbEncoded[cbByteOffset], cbASN_LENGTH_SINGLE_BYTE_MAX - cbAttrOffset);
        goto end;
    }

    // OID context: Min length (minus type & length bytes)
    if (pbEncoded[cbByteOffset] < cbCA_SECURITY_EXT_ASN_MIN - (cbAttrOffset + 2)) {
        DBG_PRINT("OID context is %u bytes but expected at least %zu bytes\n",
                  pbEncoded[cbByteOffset], cbCA_SECURITY_EXT_ASN_MIN - (cbAttrOffset + 2));
        goto end;
    }

    // OID context: Buffer size (minus type & length bytes)
    if (pbEncoded[cbByteOffset] > cbEncoded - (cbAttrOffset + 2)) {
        DBG_PRINT("OID context is %u bytes but buffer has only %zu bytes\n",
                  pbEncoded[cbByteOffset], cbEncoded - (cbAttrOffset + 2));
        goto end;
    }
    cbByteOffset++;
    cbAttrOffset = cbByteOffset;

    // OID: Tag
    if (pbEncoded[cbByteOffset] != ASN_OBJECT_IDENTIFIER) {
        DBG_PRINT("Expected a OID tag but found: 0x%x\n",
                  pbEncoded[cbByteOffset]);
        goto end;
    }
    cbByteOffset++;

    // OID: Length
    if (pbEncoded[cbByteOffset] != cbOBJECTSID_OID_VALUE) {
        DBG_PRINT("OID is %u bytes but expected %u bytes\n",
                  pbEncoded[cbByteOffset], cbOBJECTSID_OID_VALUE);
        goto end;
    }

    // OID: Buffer size (minus type & length bytes)
    if (pbEncoded[cbByteOffset] > cbEncoded - (cbAttrOffset + 2)) {
        DBG_PRINT("OID is %u bytes but buffer has only %zu bytes\n",
                  pbEncoded[cbByteOffset], cbEncoded - (cbAttrOffset + 2));
        goto end;
    }
    cbByteOffset++;

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING,
                             X509_OBJECT_IDENTIFIER,
                             pbEncoded + cbAttrOffset,
                             cbOBJECTSID_OID_TLV,
                             CRYPT_DECODE_ALLOC_FLAG,
                             NULL,     // Use LocalAlloc()
                             &ppszOid, // NOLINT(bugprone-multi-level-implicit-pointer-conversion)
                             &cbOidA)) {
        DBG_PRINT("CryptDecodeObjectEx() of X509_OBJECT_IDENTIFIER failed (err: %u)\n", GetLastError());
        goto end;
    }
    cbByteOffset += pbEncoded[cbAttrOffset + 1];
    cbAttrOffset = cbByteOffset;

    if (strcmp(szOBJECTSID_OID, *ppszOid) != 0) {
        DBG_PRINT("Expected OID is %s but decoded OID is %s\n", szOBJECTSID_OID, *ppszOid);
        goto end;
    }

    // SID context: Tag
    if (pbEncoded[cbByteOffset] != (ASN_CONTEXT | ASN_CONSTRUCTED)) {
        DBG_PRINT("Expected a context-specific constructed tag before SID but found: 0x%x\n",
                  pbEncoded[cbByteOffset]);
        goto end;
    }
    cbByteOffset++;

    // SID context: Max length
    if (pbEncoded[cbByteOffset] > cbASN_LENGTH_SINGLE_BYTE_MAX - cbAttrOffset) {
        DBG_PRINT("SID context is %u bytes but expected at most %zu bytes\n",
                  pbEncoded[cbByteOffset], cbASN_LENGTH_SINGLE_BYTE_MAX - cbAttrOffset);
        goto end;
    }

    // SID context: Min length
    if (pbEncoded[cbByteOffset] < cbASN_SID_TLV_MIN) {
        DBG_PRINT("SID context is %u bytes but expected at least %u bytes\n",
                  pbEncoded[cbByteOffset], cbASN_SID_TLV_MIN);
        goto end;
    }

    // SID context: Buffer size (minus type & length bytes)
    if (pbEncoded[cbByteOffset] > cbEncoded - (cbAttrOffset + 2)) {
        DBG_PRINT("SID context is %u bytes but buffer has only %zu bytes\n",
                  pbEncoded[cbByteOffset], cbEncoded - (cbAttrOffset + 2));
        goto end;
    }
    cbByteOffset++;
    cbAttrOffset = cbByteOffset;

    // SID: Tag
    if (pbEncoded[cbByteOffset] != ASN_OCTET_STRING) {
        DBG_PRINT("Expected a octet string tag for SID but found: 0x%x\n",
                  pbEncoded[cbByteOffset]);
        goto end;
    }
    cbByteOffset++;

    // SID: Max length
    if (pbEncoded[cbByteOffset] > cbASN_LENGTH_SINGLE_BYTE_MAX - cbAttrOffset) {
        DBG_PRINT("SID has %u bytes but expected at most %zu bytes\n",
                  pbEncoded[cbByteOffset], cbASN_LENGTH_SINGLE_BYTE_MAX - cbAttrOffset);
        goto end;
    }

    // SID: Min length
    if (pbEncoded[cbByteOffset] < cbASN_SID_VALUE_MIN) {
        DBG_PRINT("SID has %u bytes but expected at least %u bytes\n",
                  pbEncoded[cbByteOffset], cbASN_SID_VALUE_MIN);
        goto end;
    }

    // SID: Buffer size (minus type & length bytes)
    if (pbEncoded[cbByteOffset] > cbEncoded - (cbAttrOffset + 2)) {
        DBG_PRINT("SID has %u bytes but buffer has only %zu bytes\n",
                  pbEncoded[cbByteOffset], cbEncoded - (cbAttrOffset + 2));
        goto end;
    }
    cbByteOffset++;

    if (!DecodeAsnSidA(&pbEncoded[cbAttrOffset], pbEncoded[cbAttrOffset + 1] + 2, &pszSid, &cbSidA)) {
        goto end;
    }
    cbByteOffset += pbEncoded[cbAttrOffset + 1];

    if (cbByteOffset != cbEncoded) {
        DBG_PRINT("Decoded %zu bytes but buffer has only %u bytes\n", cbByteOffset, cbEncoded);
    }

    cchNumChars = strnlen_s(*ppszOid, cbOidA) + 1; // Add terminating null
    pwszOid = calloc(cchNumChars, sizeof(WCHAR));
    if (pwszOid == NULL) {
        DBG_PRINT("calloc() failed to allocate WCHAR array for OID (errno: %d)\n", errno);
        goto end;
    }

    if (mbstowcs_s(&cchNumChars, pwszOid, cchNumChars, *ppszOid, cchNumChars - 1) != 0) {
        DBG_PRINT("mbstowcs_s() failed converting OID (errno: %d)\n", errno);
        goto end;
    }

    cchNumChars = strnlen_s(pszSid, cbSidA) + 1; // Add terminating null
    pwszSid = calloc(cchNumChars, sizeof(WCHAR));
    if (pwszSid == NULL) {
        DBG_PRINT("calloc() failed to allocate WCHAR array for SID (errno: %d)\n", errno);
        goto end;
    }

    if (mbstowcs_s(&cchNumChars, pwszSid, cchNumChars, pszSid, cchNumChars - 1) != 0) {
        DBG_PRINT("mbstowcs_s() failed converting SID (errno: %d)\n", errno);
        goto end;
    }

    if (!ConvertStringSidToSidW(pwszSid, &pSid)) {
        DBG_PRINT("ConvertStringSidToSidW() failed (err: %u)\n", GetLastError());
        goto end;
    }

    if (dwFormatStrType == CRYPT_FORMAT_STR_SINGLE_LINE) {
        if (swprintf_s(pbFormat, *pcbFormat / sizeof(WCHAR), L"Object SID: %s", pwszSid) != -1) {
            bStatus = TRUE;
        } else {
            DBG_PRINT("swprintf_s() failed formatting string to format buffer (errno: %d)\n", errno);
        }

        goto end;
    }

    if (!LookupAccountSidW(NULL,
                           pSid,
                           NULL, &cbSidAccountName,
                           NULL, &cbSidAccountDomain,
                           &sidType)) {
        dwLookupError = GetLastError();
        if (dwLookupError != ERROR_INSUFFICIENT_BUFFER) {
            DBG_PRINT("LookupAccountSidW() failed (err: %u)\n", dwLookupError);
            goto lookupErr;
        }
    }

    pwszSidAccountName = calloc(cbSidAccountName, sizeof(WCHAR));
    if (pwszSidAccountName == NULL) {
        DBG_PRINT("calloc() failed to allocate WCHAR array for SID account name (errno: %d)\n", errno);
        goto end;
    }

    pwszSidAccountDomain = calloc(cbSidAccountDomain, sizeof(WCHAR));
    if (pwszSidAccountDomain == NULL) {
        DBG_PRINT("calloc() failed to allocate WCHAR array for SID domain name (errno: %d)\n", errno);
        goto end;
    }

    if (!LookupAccountSidW(NULL,
                           pSid,
                           pwszSidAccountName, &cbSidAccountName,
                           pwszSidAccountDomain, &cbSidAccountDomain,
                           &sidType)) {
        dwLookupError = GetLastError();
        DBG_PRINT("LookupAccountSidW() failed (err: %u)\n", dwLookupError);
        goto lookupErr;
    }

    if (swprintf_s(pbFormat, *pcbFormat / sizeof(WCHAR),
                   L"Account: %s\\%s\nSID: %s\n",
                   pwszSidAccountDomain, pwszSidAccountName, pwszSid) == -1) {
        DBG_PRINT("swprintf_s() failed formatting string to format buffer (errno: %d)\n", errno);
    }

    bStatus = TRUE;
    goto end;

lookupErr:
    if (swprintf_s(pbFormat, *pcbFormat / sizeof(WCHAR),
                   L"SID: %s\n\nUnable to resolve SID to account name (err: %u)\n",
                   pwszSid, dwLookupError) == -1) {
        DBG_PRINT("swprintf_s() failed formatting string to format buffer (errno: %d)\n", errno);
        goto end;
    }

    bStatus = TRUE;

end:
    // Account details
    free(pwszSidAccountDomain);
    free(pwszSidAccountName);
    LocalFree(pSid);

    // Security identifier
    free(pwszSid);
    free(pszSid);

    // Object identifier
    free(pwszOid);
    LocalFree(ppszOid); // NOLINT(bugprone-multi-level-implicit-pointer-conversion)

    DBG_EXIT(bStatus);
    return bStatus ? TRUE : SetFailureInfo(dwFormatStrType, pbFormat, *pcbFormat);
}
