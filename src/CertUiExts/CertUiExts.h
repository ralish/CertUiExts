#pragma once

_Success_(return != FALSE)
BOOL ConvertGuidToStringW(_In_ const GUID* pGuid,
                          _Outptr_result_z_ PWSTR* ppwszGuid);

_Success_(return != FALSE)
BOOL DecodeAsnGuid(_In_reads_bytes_(cbEncoded) const BYTE* pbEncoded,
                   _In_ DWORD cbEncoded,
                   _Outptr_ GUID** ppGuid);

_Success_(return != FALSE)
BOOL DecodeAsnSidA(_In_reads_bytes_(cbEncoded) const BYTE* pbEncoded,
                   _In_ DWORD cbEncoded,
                   _Outptr_result_bytebuffer_(*cbSid) PSTR* ppszSid,
                   _Out_ DWORD* cbSid);

BOOL FormatAsGuidStringW(_In_ DWORD dwFormatStrType,
                         _In_reads_bytes_(cbEncoded) const BYTE* pbEncoded,
                         _In_ DWORD cbEncoded,
                         _At_((WCHAR *)pbFormat, _Out_writes_bytes_(*pcbFormat)) void* pbFormat,
                         _Inout_ DWORD* pcbFormat);

BOOL SetFailureInfo(_In_ DWORD dwFormatStrType,
                    _At_((WCHAR *)pbFormat, _Out_writes_bytes_(cbFormat)) void* pbFormat,
                    _In_ DWORD cbFormat);

_Success_(return != FALSE)
BOOL SetFormatBufferSize(_Out_opt_ void* pbFormat,
                         _Inout_ DWORD* pcbFormat,
                         _In_ DWORD cbSize);

BOOL VerifyFormatBufferSize(_In_ DWORD cbFormat,
                            _In_ DWORD cbSize);

// GUID constants
#define GUID_SIZE_CCH (DWORD)36 // Including dashes

// String constants
#define FORMAT_FAILURE_W L"Failed to decode"

// Minimum format buffer size
#define FORMAT_MIN_SIZE_CB (32 * sizeof(WCHAR))

// CryptFormatObject: dwFormatStrType
#define CRYPT_FORMAT_STR_SINGLE_LINE 0
