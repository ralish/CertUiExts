#include "pch.h"

__declspec(dllexport)
BOOL FormatGenericAsnGuid(_In_ const DWORD dwCertEncodingType,
                          _In_ const DWORD dwFormatType,
                          _In_ const DWORD dwFormatStrType,
                          _In_opt_ const void* pFormatStruct,
                          _In_z_ const LPCSTR lpszStructType,
                          _In_reads_bytes_(cbEncoded) const BYTE* pbEncoded,
                          _In_ const DWORD cbEncoded,
                          _At_((WCHAR*)pbFormat, _Out_writes_bytes_to_opt_(*pcbFormat, *pcbFormat)) void* pbFormat,
                          _Inout_ DWORD* pcbFormat) {
    UNREFERENCED_PARAMETER(dwCertEncodingType);
    UNREFERENCED_PARAMETER(dwFormatType);
    UNREFERENCED_PARAMETER(pFormatStruct);
    UNREFERENCED_PARAMETER(lpszStructType);

    BOOL bStatus;

    DBG_ENTER(dwCertEncodingType, dwFormatStrType, lpszStructType, *pcbFormat);
    bStatus = FormatAsGuidStringW(dwFormatStrType, pbEncoded, cbEncoded, pbFormat, pcbFormat);
    DBG_EXIT(bStatus);

    return bStatus;
}

__declspec(dllexport)
BOOL FormatGenericAsnInteger(_In_ const DWORD dwCertEncodingType,
                             _In_ const DWORD dwFormatType,
                             _In_ const DWORD dwFormatStrType,
                             _In_opt_ const void* pFormatStruct,
                             _In_z_ const LPCSTR lpszStructType,
                             _In_reads_bytes_(cbEncoded) const BYTE* pbEncoded,
                             _In_ const DWORD cbEncoded,
                             _At_((WCHAR*)pbFormat, _Out_writes_bytes_to_opt_(*pcbFormat, *pcbFormat)) void* pbFormat,
                             _Inout_ DWORD* pcbFormat) {
    UNREFERENCED_PARAMETER(dwCertEncodingType);
    UNREFERENCED_PARAMETER(dwFormatType);
    UNREFERENCED_PARAMETER(pFormatStruct);
    UNREFERENCED_PARAMETER(lpszStructType);

    BOOL bStatus;

    DBG_ENTER(dwCertEncodingType, dwFormatStrType, lpszStructType, *pcbFormat);
    bStatus = FormatAsIntStringW(dwFormatStrType, pbEncoded, cbEncoded, pbFormat, pcbFormat);
    DBG_EXIT(bStatus);

    return bStatus;
}
