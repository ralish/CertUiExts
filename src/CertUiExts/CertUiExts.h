#pragma once

// Utilities: General functions
BOOL ConvertGuidToStringW(const GUID* pGuid,
                          LPWSTR*     ppwszGuid);

BOOL DecodeAsnGuid(const BYTE* pbEncoded,
                   DWORD       cbEncoded,
                   GUID**      ppGuid);

BOOL DecodeAsnSidA(const BYTE* pbEncoded,
                   DWORD       cbEncoded,
                   LPSTR*      ppszSid);

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

// Utilities: Debug functions
#ifdef _DEBUG
void OutputDebugFormatStringA(LPCSTR pszFuncName,
                              LPCSTR pszDebugFormat,
                              ...);

void FormatObjectDebugEntryA(LPCSTR pszFuncName,
                             DWORD  dwCertEncodingType,
                             DWORD  dwFormatStrType,
                             LPCSTR lpszStructType,
                             DWORD  cbFormat);

void FormatObjectDebugExitA(LPCSTR pszFuncName,
                            BOOL   bStatus);

#define DBG_PRINT(kszDebugFormatString, ...) \
    OutputDebugFormatStringA(__func__, kszDebugFormatString, __VA_ARGS__)

#define DBG_ENTER(dwCertEncodingType, dwFormatStrType, lpszStructType, cbFormat) \
    FormatObjectDebugEntryA(__func__, dwCertEncodingType, dwFormatStrType, lpszStructType, cbFormat)

#define DBG_EXIT(bStatus) \
    FormatObjectDebugExitA(__func__, bStatus)
#else
#define DBG_PRINT(kszDebugFormatString, ...) ;;
#define DBG_ENTER(dwCertEncodingType, dwFormatStrType, lpszStructType, cbFormat) ;;
#define DBG_EXIT(bStatus) ;;
#endif

// GUID constants
#define dwGUID_SIZE_CHARS (DWORD)37 // Including dashes & terminating null
#define cbGUID_SIZE_A (dwGUID_SIZE_CHARS * sizeof(CHAR))
#define cbGUID_SIZE_W (dwGUID_SIZE_CHARS * sizeof(WCHAR))

// String constants (ASCII)
#define szCRYPT_FORMAT_OBJECT "CryptDllFormatObject"

// String constants (Unicode)
#define wszDLL_NAME L"CertUiExts.dll"
#define wszEXE_NAME L"CertUiExtsReg.exe"
#define wszFORMAT_FAILURE L"Failed to decode"
