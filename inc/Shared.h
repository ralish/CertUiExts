#pragma once

#ifdef _DEBUG
void OutputDebugFormatStringA(LPCSTR pszFuncName,
                              LPCSTR pszDebugFormat,
                              ...);

void FormatObjectDebugEntryA(LPCSTR pszFuncName,
                             DWORD dwCertEncodingType,
                             DWORD dwFormatStrType,
                             LPCSTR lpszStructType,
                             DWORD cbFormat);

void FormatObjectDebugExitA(LPCSTR pszFuncName,
                            BOOL bStatus);

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
