#include "pch.h"

#include <wincrypt.h>
#include <wintrust.h>

#include "Asn1.h"

/*
 * SPC Statement Type
 * 1.3.6.1.4.1.311.2.1.11
 *
 * [MS-OSHARED]: Office Common Data Types and Objects Structures
 * Section 2.3.2.4.4.1: SpcStatementType
 */
__declspec(dllexport)
BOOL FormatAuthenticodeSpcStatementType(_In_ const DWORD dwCertEncodingType,
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

    // Sequence
    CRYPT_SEQUENCE_OF_ANY* pbAsnSeq = NULL;
    DWORD cbAsnSeq = 0;

    // Object identifier
    PSTR* ppszOid = NULL;
    DWORD cbOidA = 0;

    // Statement type
    WCHAR* pwszType;

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING,
                             X509_SEQUENCE_OF_ANY,
                             pbEncoded,
                             cbEncoded,
                             CRYPT_DECODE_ALLOC_FLAG,
                             NULL,      // Use LocalAlloc()
                             &pbAsnSeq, // NOLINT(bugprone-multi-level-implicit-pointer-conversion)
                             &cbAsnSeq)) {
        DBG_PRINT("CryptDecodeObjectEx() of X509_SEQUENCE_OF_ANY failed (err: %u)\n", GetLastError());
        goto end;
    }

    if (pbAsnSeq->cValue != 1) {
        DBG_PRINT("ASN.1 sequence has %d elements but expected 1 element\n", pbAsnSeq->cValue);
        goto end;
    }

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING,
                             X509_OBJECT_IDENTIFIER,
                             pbAsnSeq->rgValue[0].pbData,
                             pbAsnSeq->rgValue[0].cbData,
                             CRYPT_DECODE_ALLOC_FLAG,
                             NULL,     // Use LocalAlloc()
                             &ppszOid, // NOLINT(bugprone-multi-level-implicit-pointer-conversion)
                             &cbOidA)) {
        DBG_PRINT("CryptDecodeObjectEx() of X509_OBJECT_IDENTIFIER failed (err: %u)\n", GetLastError());
        goto end;
    }

    if (strcmp(*ppszOid, SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID) == 0) {
        pwszType = L"Individual\n";
    } else if (strcmp(*ppszOid, SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID) == 0) {
        pwszType = L"Commercial\n";
    } else {
        pwszType = L"Invalid OID\n";
    }

    if (wcscpy_s(pbFormat, *pcbFormat / sizeof(WCHAR), pwszType) != 0) {
        DBG_PRINT("wcscpy_s() failed copying string to format buffer (errno: %d)\n", errno);
        goto end;
    }

    bStatus = TRUE;

end:
    LocalFree(ppszOid); // NOLINT(bugprone-multi-level-implicit-pointer-conversion)
    LocalFree(pbAsnSeq);

    DBG_EXIT(bStatus);
    return bStatus ? TRUE : SetFailureInfo(dwFormatStrType, pbFormat, *pcbFormat);
}
