#pragma once

BOOL ConvertGuidToStringW(const GUID* pGuid,
                          LPWSTR*     ppwszGuid);

BOOL DecodeAsnGuid(const BYTE* pbEncoded,
                   DWORD       cbEncoded,
                   GUID**      ppGuid);

BOOL DecodeAsnSidA(const BYTE* pbEncoded,
                   DWORD       cbEncoded,
                   LPSTR*      ppszSid,
                   DWORD*      cbSid);

BOOL FormatAsGuidStringW(DWORD       dwFormatStrType,
                         const BYTE* pbEncoded,
                         DWORD       cbEncoded,
                         void*       pbFormat,
                         DWORD*      pcbFormat);

BOOL SetFailureInfo(DWORD        dwFormatStrType,
                    void*        pbFormat,
                    const DWORD* pcbFormat);

BOOL SetFormatBufferSize(const void* pbFormat,
                         DWORD*      pcbFormat,
                         DWORD       dwSize);

BOOL VerifyFormatBufferSize(const DWORD* pcbFormat,
                            DWORD        dwSize);

// GUID constants
#define dwGUID_SIZE_CHARS (DWORD)36 // Including dashes

// String constants (Unicode)
#define wszFORMAT_FAILURE L"Failed to decode"
