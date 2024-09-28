#include "pch.h"

#include <stdlib.h>
#include <string.h>

#include <wincrypt.h>
#include <wintrust.h>

#include "Shared.h"
#include "OIDs.h"

#include "CertUiExts.h"

__declspec(dllexport)
BOOL FormatAuthenticodeSpcStatementType(_In_ const DWORD dwCertEncodingType,
                                        _In_ const DWORD dwFormatType,
                                        _In_ const DWORD dwFormatStrType,
                                        _In_opt_ const void* pFormatStruct,
                                        _In_opt_ const LPCSTR lpszStructType,
                                        _In_reads_bytes_(cbEncoded) const BYTE* pbEncoded,
                                        _In_ const DWORD cbEncoded,
                                        _At_((WCHAR *)pbFormat,
                                             _Out_writes_bytes_to_opt_(*pcbFormat, *pcbFormat)) void* pbFormat,
                                        _Inout_ DWORD* pcbFormat) {
    UNREFERENCED_PARAMETER(dwCertEncodingType);
    UNREFERENCED_PARAMETER(dwFormatType);
    UNREFERENCED_PARAMETER(pFormatStruct);
    UNREFERENCED_PARAMETER(lpszStructType);

    BOOL bStatus = FALSE;
    DWORD cchFormat;

    // ASN.1: Sequence
    CRYPT_SEQUENCE_OF_ANY* pbAsnSeq = NULL;
    DWORD cbAsnSeq = 0;

    // ASN.1: Sequence->OID
    PSTR* ppszOid = NULL;
    DWORD cbOidA = 0;

    DBG_ENTER(dwCertEncodingType, dwFormatStrType, lpszStructType, *pcbFormat);

    if (SetFormatBufferSize(pbFormat, pcbFormat, cbAUTHENTICODE_SPC_STATEMENT_TYPE_BUFFER)) {
        return TRUE;
    }

    if (!VerifyFormatBufferSize(*pcbFormat, cbAUTHENTICODE_SPC_STATEMENT_TYPE_BUFFER)) {
        return FALSE;
    }

    // ASN.1: Sequence
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING,
                             X509_SEQUENCE_OF_ANY,
                             pbEncoded,
                             cbEncoded,
                             CRYPT_DECODE_ALLOC_FLAG,
                             NULL, // Use LocalAlloc()
                             &pbAsnSeq,
                             &cbAsnSeq)) {
        DBG_PRINT("CryptDecodeObjectEx() of X509_SEQUENCE_OF_ANY failed (err: %u)\n", GetLastError());
        return bStatus;
    }

    if (pbAsnSeq->cValue != 1) {
        DBG_PRINT("ASN.1 sequence has %d elements but expected only one\n", pbAsnSeq->cValue);
        goto end;
    }

    // ASN.1: Sequence->OID
    if (!CryptDecodeObjectEx(X509_ASN_ENCODING,
                             X509_OBJECT_IDENTIFIER,
                             pbAsnSeq->rgValue[0].pbData,
                             pbAsnSeq->rgValue[0].cbData,
                             CRYPT_DECODE_ALLOC_FLAG,
                             NULL, // Use LocalAlloc()
                             &ppszOid,
                             &cbOidA)) {
        DBG_PRINT("CryptDecodeObjectEx() of X509_OBJECT_IDENTIFIER failed (err: %u)\n", GetLastError());
        return bStatus;
    }

    cchFormat = *pcbFormat / sizeof(WCHAR);
    if (strcmp(*ppszOid, SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID) == 0) {
        if (wcscpy_s(pbFormat, cchFormat, L"Individual\n") != 0) {
            DBG_PRINT("wcscpy_s() failed copying string to output buffer (errno: %d)\n", errno);
            goto end;
        }
    } else if (strcmp(*ppszOid, SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID) == 0) {
        if (wcscpy_s(pbFormat, cchFormat, L"Commercial\n") != 0) {
            DBG_PRINT("wcscpy_s() failed copying string to output buffer (errno: %d)\n", errno);
            goto end;
        }
    } else {
        if (wcscpy_s(pbFormat, cchFormat, L"Invalid OID\n") != 0) {
            DBG_PRINT("wcscpy_s() failed copying string to output buffer (errno: %d)\n", errno);
            goto end;
        }
    }

    bStatus = TRUE;

end:
    LocalFree(ppszOid);
    LocalFree(pbAsnSeq);

    DBG_EXIT(bStatus);
    return bStatus ? TRUE : SetFailureInfo(dwFormatStrType, pbFormat, *pcbFormat);
}
