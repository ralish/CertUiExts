#pragma once

BOOL ConvertGuidToStringW(const GUID* pGuid,
                          PWSTR* ppwszGuid);

BOOL DecodeAsnGuid(const BYTE* pbEncoded,
                   DWORD cbEncoded,
                   GUID** ppGuid);

BOOL DecodeAsnSidA(const BYTE* pbEncoded,
                   DWORD cbEncoded,
                   PSTR* ppszSid,
                   DWORD* cbSid);

BOOL FormatAsGuidStringW(DWORD dwFormatStrType,
                         const BYTE* pbEncoded,
                         DWORD cbEncoded,
                         void* pbFormat,
                         DWORD* pcbFormat);

BOOL SetFailureInfo(DWORD dwFormatStrType,
                    void* pbFormat,
                    DWORD cbFormat);

BOOL SetFormatBufferSize(const void* pbFormat,
                         DWORD* pcbFormat,
                         DWORD cbSize);

BOOL VerifyFormatBufferSize(DWORD cbFormat,
                            DWORD cbSize);

// GUID constants
#define cchGUID_SIZE (DWORD)36 // Including dashes

// String constants
#define wszFORMAT_FAILURE L"Failed to decode"

// Minimum format buffer size
#define cbFORMAT_MIN_SIZE (32 * sizeof(WCHAR))

// CryptFormatObject: dwFormatStrType
#define CRYPT_FORMAT_STR_SINGLE_LINE 0
