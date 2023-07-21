#include "pch.h"

#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>

#include <sddl.h>
#include <wincrypt.h>

#include "Shared.h"
#include "ASN1.h"
#include "OIDs.h"

#include "CertUiExts.h"

/*
 * CA Security
 * 1.3.6.1.4.1.311.25.2
 */
__declspec(dllexport)
BOOL FormatNtdsCaSecurityExt(_In_ const DWORD dwCertEncodingType,
                             _In_ const DWORD dwFormatType,
                             _In_ const DWORD dwFormatStrType,
                             _In_opt_ const void* pFormatStruct,
                             _In_opt_ const LPCSTR lpszStructType,
                             _In_reads_bytes_(cbEncoded) const BYTE* pbEncoded,
                             _In_ const DWORD cbEncoded,
                             _At_((WCHAR *)pbFormat, _Out_writes_bytes_to_opt_(*pcbFormat, *pcbFormat)) void* pbFormat,
                             _Inout_ DWORD* pcbFormat) {
    BOOL bStatus = FALSE;
    size_t stNumChars;

    // OID
    BYTE pbAsnOidTlv[cbNTDS_OBJECTSID_OID_TLV];
    LPSTR* ppszOid = NULL;
    LPWSTR pwszOid = NULL;
    DWORD cbOidA = 0;

    // SID
    BYTE* pbAsnSidTlv = NULL;
    DWORD cbAsnSidTlv;
    DWORD cbSidA;
    LPSTR pszSid = NULL;
    LPWSTR pwszSid = NULL;

    // Account details
    PSID pSid = NULL;
    LPWSTR pwszSidAccountName = NULL;
    DWORD cbSidAccountName = 0;
    LPWSTR pwszSidAccountDomain = NULL;
    DWORD cbSidAccountDomain = 0;
    SID_NAME_USE sidType;

    DBG_ENTER(dwCertEncodingType, dwFormatStrType, lpszStructType, *pcbFormat);

    if (SetFormatBufferSize(pbFormat, pcbFormat, cbNTDS_CA_SECURITY_EXT_BUFFER)) {
        return TRUE;
    }

    if (!VerifyFormatBufferSize(pcbFormat, cbNTDS_CA_SECURITY_EXT_BUFFER)) {
        return FALSE;
    }

    if (cbEncoded < cbNTDS_CA_SECURITY_EXT_ASN_MIN) {
        DBG_PRINT("ASN.1 structure is %u bytes but expected at least %u bytes\n",
                  cbEncoded, cbNTDS_CA_SECURITY_EXT_BUFFER);
        goto end;
    }

    // Sequence tag
    if (!(pbEncoded[0] == ASN_SEQUENCE
        && pbEncoded[1] >= cbNTDS_CA_SECURITY_EXT_ASN_MIN - 2 // Type & length bytes
        && pbEncoded[1] < cbASN_LENGTH_SINGLE_BYTE_MAX)) {
        DBG_PRINT("ASN.1 structure doesn't start with expected sequence tag\n", NULL);
        goto end;
    }

    // Context-specific tag preceding the OID
    if (!(pbEncoded[2] == (ASN_CONTEXT | ASN_CONSTRUCTED)
        && pbEncoded[3] >= cbNTDS_CA_SECURITY_EXT_ASN_MIN - 4 // Type & length bytes inc. previous
        && pbEncoded[3] < cbASN_LENGTH_SINGLE_BYTE_MAX)) {
        DBG_PRINT("ASN.1 structure doesn't have expected context-specific tag before OID\n", NULL);
        goto end;
    }

    // Object identifier
    if (!(pbEncoded[4] == ASN_OBJECT_IDENTIFIER
        && pbEncoded[5] == cbNTDS_OBJECTSID_OID_VALUE)) {
        DBG_PRINT("ASN.1 structure doesn't have expected object identifier tag\n", NULL);
        goto end;
    }

    // Context-specific tag preceding the SID
    if (!(pbEncoded[16] == (ASN_CONTEXT | ASN_CONSTRUCTED)
        && pbEncoded[17] >= cbASN_SID_TLV_MIN
        && pbEncoded[17] < cbASN_LENGTH_SINGLE_BYTE_MAX)) {
        DBG_PRINT("ASN.1 structure doesn't have expected context-specific tag before SID\n", NULL);
        goto end;
    }

    // Security identifier encoded as octet string
    if (!(pbEncoded[18] == ASN_OCTET_STRING
        && pbEncoded[19] >= cbASN_SID_VALUE_MIN
        && pbEncoded[20] < cbASN_LENGTH_SINGLE_BYTE_MAX)) {
        DBG_PRINT("ASN.1 structure doesn't have expected octet string tag for encoded SID\n", NULL);
        goto end;
    }

    if (memcpy_s(pbAsnOidTlv, sizeof(pbAsnOidTlv), pbEncoded + 4, sizeof(pbAsnOidTlv)) != 0) {
        DBG_PRINT("memcpy_s() failed copying ASN.1 OID TLV (errno: %d)\n", errno);
        goto end;
    }

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING,
                             X509_OBJECT_IDENTIFIER,
                             pbAsnOidTlv,
                             sizeof(pbAsnOidTlv),
                             CRYPT_DECODE_ALLOC_FLAG,
                             NULL, // Use LocalAlloc()
                             &ppszOid,
                             &cbOidA)) {
        DBG_PRINT("CryptDecodeObjectEx() failed (err: %u)\n", GetLastError());
        goto end;
    }

    if (strcmp(szNTDS_OBJECTSID_OID, *ppszOid) != 0) {
        DBG_PRINT("Expected OID is %s but decoded OID is %s\n", szNTDS_OBJECTSID_OID, *ppszOid);
        goto end;
    }

    stNumChars = strnlen_s(*ppszOid, cbOidA) + 1; // Add terminating null
    pwszOid = calloc(stNumChars, sizeof(WCHAR));
    if (pwszOid == NULL) {
        DBG_PRINT("calloc() failed to allocate WCHAR array for OID (errno: %d)\n", errno);
        goto end;
    }

    if (mbstowcs_s(&stNumChars, pwszOid, stNumChars, *ppszOid, stNumChars - 1) != 0) {
        DBG_PRINT("mbstowcs_s() failed converting OID (errno: %d)\n", errno);
        goto end;
    }

    cbAsnSidTlv = pbEncoded[19] + 2; // Extra 2 bytes for type & length
    pbAsnSidTlv = malloc(cbAsnSidTlv);
    if (pbAsnSidTlv == NULL) {
        DBG_PRINT("malloc() failed to allocate %u bytes for ASN.1 SID TLV (errno: %d)\n", cbAsnSidTlv, errno);
        goto end;
    }

    if (memcpy_s(pbAsnSidTlv, cbAsnSidTlv, pbEncoded + 18, cbAsnSidTlv) != 0) {
        DBG_PRINT("memcpy_s() failed copying ASN.1 SID TLV (errno: %d)\n", errno);
        goto end;
    }

    if (!DecodeAsnSidA(pbAsnSidTlv, cbAsnSidTlv, &pszSid, &cbSidA)) {
        goto end;
    }

    stNumChars = strnlen_s(pszSid, cbSidA) + 1; // Add terminating null
    pwszSid = calloc(stNumChars, sizeof(WCHAR));
    if (pwszSid == NULL) {
        DBG_PRINT("calloc() failed to allocate WCHAR array for SID (errno: %d)\n", errno);
        goto end;
    }

    if (mbstowcs_s(&stNumChars, pwszSid, stNumChars, pszSid, stNumChars - 1) != 0) {
        DBG_PRINT("mbstowcs_s() failed converting SID (errno: %d)\n", errno);
        goto end;
    }

    if (!ConvertStringSidToSidW(pwszSid, &pSid)) {
        DBG_PRINT("ConvertStringSidToSidW() failed (err: %d)\n", GetLastError());
        goto end;
    }

    // Single line display
    if (dwFormatStrType == 0) {
        if (swprintf_s(pbFormat, *pcbFormat / sizeof(WCHAR), L"Object SID: %s", pwszSid) != -1) {
            bStatus = TRUE;
        }

        goto end;
    }

    if (!LookupAccountSidW(NULL,
                           pSid,
                           NULL, &cbSidAccountName,
                           NULL, &cbSidAccountDomain,
                           &sidType)) {
        const DWORD dwLastError = GetLastError();
        if (dwLastError != ERROR_INSUFFICIENT_BUFFER) {
            DBG_PRINT("LookupAccountSidW() failed (err: %u)\n", dwLastError);
            goto end;
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
        DBG_PRINT("LookupAccountSidW() failed (err: %d)\n", GetLastError());
        goto end;
    }

    if (swprintf_s(pbFormat, *pcbFormat / sizeof(WCHAR),
                   L"Account: %s\\%s\nSID: %s\n",
                   pwszSidAccountDomain, pwszSidAccountName, pwszSid) != -1) {
        bStatus = TRUE;
    }

end:
    // Account details
    free(pwszSidAccountDomain);
    free(pwszSidAccountName);
    LocalFree(pSid);

    // SID
    free(pwszSid);
    free(pszSid);
    free(pbAsnSidTlv);

    // OID
    free(pwszOid);
    LocalFree(ppszOid);

    DBG_EXIT(bStatus);
    return bStatus ? TRUE : SetFailureInfo(dwFormatStrType, pbFormat, pcbFormat);
}
