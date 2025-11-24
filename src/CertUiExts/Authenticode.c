#include "pch.h"

#include <wincrypt.h>
#include <wintrust.h>

#include "Asn1.h"
#include "Authenticode.h"

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

/*
 * SPC Publisher Information
 * 1.3.6.1.4.1.311.2.1.12
 *
 * [MS-OSHARED]: Office Common Data Types and Objects Structures
 * Section 2.3.2.4.4.2: SpcSpOpusInfo
 */
__declspec(dllexport)
BOOL FormatAuthenticodeSpcPublisherInfo(_In_ const DWORD dwCertEncodingType,
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

    if (SetFormatBufferSize(pbFormat, pcbFormat, cbSPC_PUBLISHER_INFO_BUFFER)) {
        return TRUE;
    }

    if (!VerifyFormatBufferSize(*pcbFormat, cbSPC_PUBLISHER_INFO_BUFFER)) {
        return FALSE;
    }

    BOOL bStatus = FALSE;
    BOOL bDuplicate = FALSE;

    // Sequence
    CRYPT_SEQUENCE_OF_ANY* pbAsnSeq = NULL;
    DWORD cbAsnSeq = 0;

    // Program name (Project)
    BOOL bProgramName = FALSE;
    WCHAR wszProgName[cbASN_LENGTH_SINGLE_BYTE_MAX / sizeof(WCHAR) + 1] = L"";

    // More information (URL)
    BOOL bMoreInfo = FALSE;
    CHAR szMoreInfo[cbASN_LENGTH_SINGLE_BYTE_MAX + 1] = "";
    WCHAR wszMoreInfo[cbASN_LENGTH_SINGLE_BYTE_MAX / sizeof(WCHAR) + 1] = L"";

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

    switch (pbAsnSeq->cValue) {
        case 0:
            if (dwFormatStrType == CRYPT_FORMAT_STR_SINGLE_LINE) {
                if (wcscpy_s(pbFormat, *pcbFormat / sizeof(WCHAR), L"(empty)") == 0) {
                    bStatus = TRUE;
                } else {
                    DBG_PRINT("wcscpy_s() failed copying string to format buffer (errno: %d)\n", errno);
                }
            } else {
                bStatus = TRUE;
            }

            goto end;
        case 1:
        case 2:
            break;
        default:
            DBG_PRINT("ASN.1 sequence has %d elements but expected at most 2 elements\n", pbAsnSeq->cValue);
            goto end;
    }

    for (DWORD i = 0; i < pbAsnSeq->cValue; i++) {
        BYTE* pbData = pbAsnSeq->rgValue[i].pbData;
        const DWORD cbData = pbAsnSeq->rgValue[i].cbData;

        if (cbData < 4) {
            DBG_PRINT("ASN.1 sequence field %u is %u bytes but expected at least 4 bytes\n", i, cbData);
            goto end;
        }

        switch (pbData[0]) {
            case SPC_PUBLISHER_INFO_PROGNAME_TAG:
                if (bProgramName) {
                    bDuplicate = TRUE;
                } else {
                    bProgramName = TRUE;
                }
                break;
            case SPC_PUBLISHER_INFO_MOREINFO_TAG:
                if (bMoreInfo) {
                    bDuplicate = TRUE;
                } else {
                    bMoreInfo = TRUE;
                }
                break;
            default:
                DBG_PRINT("Unexpected outer tag: 0x%x\n", pbData[0]);
                goto end;
        }

        if (bDuplicate) {
            DBG_PRINT("Encountered duplicate tag: 0x%x\n", pbData[0]);
            goto end;
        }

        // Only program name matters if single-line format
        if (pbData[0] != SPC_PUBLISHER_INFO_PROGNAME_TAG && dwFormatStrType == CRYPT_FORMAT_STR_SINGLE_LINE) {
            continue;
        }

        if (pbData[1] > cbASN_LENGTH_SINGLE_BYTE_MAX) {
            DBG_PRINT("Length is greater than %u bytes\n", cbASN_LENGTH_SINGLE_BYTE_MAX);
            return FALSE;
        }

        if (pbData[1] != cbData - 2) {
            DBG_PRINT("Unexpected outer length: %u bytes\n", pbData[1]);
            return FALSE;
        }

        if (pbData[2] != ASN_CONTEXT) {
            DBG_PRINT("Unexpected inner tag: 0x%x\n", pbData[2]);
            return FALSE;
        }

        if (pbData[3] > cbASN_LENGTH_SINGLE_BYTE_MAX) {
            DBG_PRINT("Length is greater than %u bytes\n", cbASN_LENGTH_SINGLE_BYTE_MAX);
            return FALSE;
        }

        if (pbData[3] != cbData - 4) {
            DBG_PRINT("Unexpected inner length: %u bytes\n", pbData[3]);
            return FALSE;
        }

        if (pbData[0] == SPC_PUBLISHER_INFO_PROGNAME_TAG) {
            // Program name is essentially UTF-16BE and not null-terminated
            const WCHAR* pwszSrc = (WCHAR*)&pbData[4];
            const BYTE cchSrc = pbData[3] / sizeof(WCHAR);
            WCHAR* pwszDst = (WCHAR*)&wszProgName;

            // Swap bytes to convert to UTF-16LE and add terminating null
            for (BYTE ch = 0; ch < cchSrc; ch++) {
                pwszDst[ch] = _byteswap_ushort(pwszSrc[ch]);
            }
            pwszDst[cchSrc] = L'\0';
        } else if (pbData[0] == SPC_PUBLISHER_INFO_MOREINFO_TAG) {
            // More info is essentially ASCII and not null-terminated
            const CHAR* pszSrc = (CHAR*)&pbData[4];
            const BYTE cchSrc = pbData[3];
            CHAR* pszDst = (CHAR*)&szMoreInfo;
            size_t cchConverted;

            // Add terminating null
            for (BYTE ch = 0; ch < cchSrc; ch++) {
                pszDst[ch] = pszSrc[ch];
            }
            pszDst[cchSrc] = '\0';

            if (mbstowcs_s(&cchConverted,
                           (WCHAR*)&wszMoreInfo, sizeof(wszMoreInfo) / sizeof(WCHAR),
                           (CHAR*)&szMoreInfo, sizeof(szMoreInfo) - 1) != 0) {
                DBG_PRINT("mbstowcs_s() failed converting URL (errno: %d)\n", errno);
                goto end;
            }
        }
    }

    if (dwFormatStrType == CRYPT_FORMAT_STR_SINGLE_LINE) {
        const WCHAR* pwszSrc = bProgramName ? (WCHAR*)&wszProgName : L"(empty)";

        if (wcscpy_s(pbFormat, *pcbFormat / sizeof(WCHAR), pwszSrc) == 0) {
            bStatus = TRUE;
        } else {
            DBG_PRINT("wcscpy_s() failed copying string to format buffer (errno: %d)\n", errno);
        }

        goto end;
    }

    ((WCHAR*)pbFormat)[0] = L'\0';
    if (bProgramName) {
        if (swprintf_s((WCHAR*)pbFormat, *pcbFormat / sizeof(WCHAR),
                       L"Project: %s\n", (WCHAR*)&wszProgName) == -1) {
            DBG_PRINT("swprintf_s() failed formatting string to format buffer (errno: %d)\n", errno);
            goto end;
        }
    }

    if (bMoreInfo) {
        if (swprintf_s((WCHAR*)pbFormat, *pcbFormat / sizeof(WCHAR),
                       L"%sURL: %s\n", (WCHAR*)pbFormat, (WCHAR*)&wszMoreInfo) == -1) {
            DBG_PRINT("swprintf_s() failed formatting string to format buffer (errno: %d)\n", errno);
            goto end;
        }
    }

    bStatus = TRUE;

end:
    LocalFree(pbAsnSeq);

    DBG_EXIT(bStatus);
    return bStatus ? TRUE : SetFailureInfo(dwFormatStrType, pbFormat, *pcbFormat);
}
