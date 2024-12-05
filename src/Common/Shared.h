#pragma once

#ifdef _DEBUG
void OutputDebugFormatStringA(_In_z_ PCSTR pszFuncName,
                              _Printf_format_string_ PCSTR pszDebugFormat,
                              ...);

void FormatObjectDebugEntryA(_In_z_ PCSTR pszFuncName,
                             _In_ DWORD dwCertEncodingType,
                             _In_ DWORD dwFormatStrType,
                             _In_z_ PCSTR pszStructType,
                             _In_ DWORD cbFormat);

void FormatObjectDebugExitA(_In_z_ PCSTR pszFuncName,
                            _In_ BOOL bStatus);

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
