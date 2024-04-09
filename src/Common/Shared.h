#pragma once

#ifdef _DEBUG
void OutputDebugFormatStringA(PCSTR pszFuncName,
                              PCSTR pszDebugFormat,
                              ...);

void FormatObjectDebugEntryA(PCSTR pszFuncName,
                             DWORD dwCertEncodingType,
                             DWORD dwFormatStrType,
                             PCSTR pszStructType,
                             DWORD cbFormat);

void FormatObjectDebugExitA(PCSTR pszFuncName,
                            BOOL bStatus);

#define DBG_PRINT(kszDebugFormatString, ...) \
    OutputDebugFormatStringA(__func__, kszDebugFormatString, __VA_ARGS__)

#define DBG_ENTER(dwCertEncodingType, dwFormatStrType, pszStructType, cbFormat) \
    FormatObjectDebugEntryA(__func__, dwCertEncodingType, dwFormatStrType, pszStructType, cbFormat)

#define DBG_EXIT(bStatus) \
    FormatObjectDebugExitA(__func__, bStatus)
#else
#define DBG_PRINT(kszDebugFormatString, ...) ;;
#define DBG_ENTER(dwCertEncodingType, dwFormatStrType, pszStructType, cbFormat) ;;
#define DBG_EXIT(bStatus) ;;
#endif
