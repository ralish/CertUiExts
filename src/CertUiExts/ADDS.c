#include "pch.h"

#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <string.h>

#include <sddl.h>
#include <wincrypt.h>

#include "CertUiExts.h"
#include "ASN.h"
#include "OIDs.h"

/*
 * CA Security
 * 1.3.6.1.4.1.311.25.2
 */
__declspec(dllexport)
BOOL FormatNtdsCaSecurityExt(_In_ DWORD dwCertEncodingType,
                             _In_ DWORD dwFormatType,
                             _In_ DWORD dwFormatStrType,
                             _In_opt_ void* pFormatStruct,
                             _In_opt_ LPCSTR lpszStructType,
                             _In_reads_bytes_(cbEncoded) const BYTE* pbEncoded,
                             _In_ DWORD cbEncoded,
                             _At_((WCHAR *)pbFormat, _Out_writes_bytes_to_opt_(*pcbFormat, *pcbFormat)) void* pbFormat,
                             _Inout_ DWORD* pcbFormat)
{
    BOOL bStatus = FALSE;

    // OID
    BYTE   pbAsnOidTlv[cbNTDS_OBJECTSID_OID_TLV];
    LPSTR* ppszOid = NULL;
    LPWSTR pwszOid = NULL;
    DWORD  cbOidLenA = 0;
    size_t cbOidLenW;

    // SID
    BYTE*  pbAsnSidTlv = NULL;
    DWORD  cbAsnSidTlv;
    LPSTR  pszSid = NULL;
    LPWSTR pwszSid = NULL;
    size_t cbSidLenW;

    // Account details
    PSID         pSid = NULL;
    LPWSTR       pwszSidAccountName = NULL;
    DWORD        cbSidAccountName = 0;
    LPWSTR       pwszSidAccountDomain = NULL;
    DWORD        cbSidAccountDomain = 0;
    SID_NAME_USE sidType;

    DBG_ENTER(dwCertEncodingType, dwFormatStrType, lpszStructType, *pcbFormat);

    if (SetFormatBufferSize(pbFormat, pcbFormat, cbNTDS_CA_SECURITY_EXT_BUFFER)) {
        SetLastError(ERROR_MORE_DATA);
        return TRUE;
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
                             &cbOidLenA)) {
        DBG_PRINT("CryptDecodeObjectEx() failed (err: %u)\n", GetLastError());
        goto end;
    }

    if (strcmp(szNTDS_OBJECTSID_OID, *ppszOid) != 0) {
        DBG_PRINT("Expected OID is %s but decoded OID is %s\n", szNTDS_OBJECTSID_OID, *ppszOid);
        goto end;
    }

    cbOidLenW = strlen(*ppszOid) * sizeof(WCHAR) + sizeof(WCHAR); // Terminating null
    pwszOid = malloc(cbOidLenW);
    if (pwszOid == NULL) {
        DBG_PRINT("malloc() failed to allocate %u bytes for wide OID string (errno: %d)\n", (DWORD)cbOidLenW, errno);
        goto end;
    }

    if (mbstowcs_s(&cbOidLenW, pwszOid, cbOidLenW / sizeof(WCHAR), *ppszOid, strlen(*ppszOid)) != 0) {
        DBG_PRINT("mbstowcs_s() failed converting ASCII OID string to wide OID string (errno: %d)\n", errno);
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

    if (!DecodeAsnSidA(pbAsnSidTlv, cbAsnSidTlv, &pszSid)) {
        goto end;
    }

    cbSidLenW = strlen(pszSid) * sizeof(WCHAR) + sizeof(WCHAR); // Terminating null
    pwszSid = malloc(cbSidLenW);
    if (pwszSid == NULL) {
        DBG_PRINT("malloc() failed to allocate %u bytes for wide SID string (errno: %d)\n", (DWORD)cbSidLenW, errno);
        goto end;
    }

    if (mbstowcs_s(&cbSidLenW, pwszSid, cbSidLenW / sizeof(WCHAR), pszSid, strlen(pszSid)) != 0) {
        DBG_PRINT("mbstowcs_s() failed converting ASCII SID string to wide SID string (errno: %d)\n", errno);
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

    cbSidAccountName = cbSidAccountName * sizeof(WCHAR);
    pwszSidAccountName = malloc(cbSidAccountName);
    if (pwszSidAccountName == NULL) {
        DBG_PRINT("malloc() failed to allocate %u bytes for SID account name (errno: %d)\n", cbSidAccountName, errno);
        goto end;
    }

    cbSidAccountDomain = cbSidAccountDomain * sizeof(WCHAR);
    pwszSidAccountDomain = malloc(cbSidAccountDomain);
    if (pwszSidAccountDomain == NULL) {
        DBG_PRINT("malloc() failed to allocate %u bytes for SID domain name (errno: %d)\n", cbSidAccountDomain, errno);
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
