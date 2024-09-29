#include "pch.h"

#include <shlwapi.h>

// Set to false if any (un)registration returns false
BOOL g_bRegStatus = TRUE;

// DLL path used in OID info & function registrations
WCHAR g_wszDllPath[MAX_PATH * sizeof(WCHAR)];

void DisplayHelp(_In_ const BOOL bInvalidParam) {
    if (bInvalidParam) {
        wprintf_s(L"An invalid parameter was provided.\n\n");
    }

    wprintf_s(L"Certificate UI Extensions\n\n");
    wprintf_s(L"Usage: %s [/i | /u]\n", wszEXE_NAME);
    wprintf_s(L"  /i    Register the extension\n");
    wprintf_s(L"  /u    Unregister the extension");
}

BOOL GetDllPath(void) {
    BOOL bStatus = FALSE;
    DWORD dwPathLen;

    dwPathLen = GetModuleFileNameW(NULL, g_wszDllPath, MAX_PATH * sizeof(WCHAR));
    if (dwPathLen == 0) {
        wprintf_s(L"Retrieving executable path failed (err: %d)", GetLastError());
        goto end;
    }

    if (dwPathLen >= MAX_PATH * sizeof(WCHAR)) {
        wprintf_s(L"Retrieved executable path exceeded MAX_SIZE.");
        goto end;
    }

    if (!PathRemoveFileSpecW(g_wszDllPath)) {
        wprintf_s(L"Failed to remove file from executable path.");
        goto end;
    }

    if (PathCombineW(g_wszDllPath, g_wszDllPath, wszDLL_NAME) == NULL) {
        wprintf_s(L"Failed to combine directory path with DLL file.");
        goto end;
    }

    bStatus = TRUE;

end:
    return bStatus;
}

#pragma region Install

BOOL RegisterOIDInfo(_In_z_ const PSTR pszOID,
                     _In_z_ const PWSTR pwszName,
                     _In_ const DWORD dwGroupId) {
    BOOL bStatus = FALSE;
    PCRYPT_OID_INFO pOIDInfo;

    wprintf_s(L"[%s] Registering OID info ... ", pwszName);

    pOIDInfo = malloc(sizeof(CRYPT_OID_INFO));
    if (pOIDInfo == NULL) {
        goto end;
    }

    memset(pOIDInfo, 0, sizeof(CRYPT_OID_INFO));

    pOIDInfo->cbSize = sizeof(CRYPT_OID_INFO);
    pOIDInfo->pszOID = pszOID;
    pOIDInfo->pwszName = pwszName;
    pOIDInfo->dwGroupId = dwGroupId;

    bStatus = CryptRegisterOIDInfo(pOIDInfo, 0);
    free(pOIDInfo);

end:
    if (g_bRegStatus) {
        g_bRegStatus = bStatus;
    }

    bStatus ? wprintf_s(L"OK.\n") : wprintf_s(L"Failed.\n");
    return bStatus;
}

BOOL RegisterOIDFunction(_In_z_ const PSTR pszOID,
                         _In_z_ const PWSTR pwszName,
                         _In_z_ const PSTR pszFuncName,
                         _In_z_ const PSTR pszOverrideFuncName) {
    BOOL bStatus;

    wprintf_s(L"[%s] Registering OID function ... ", pwszName);

    bStatus = CryptRegisterOIDFunction(X509_ASN_ENCODING,
                                       pszFuncName,
                                       pszOID,
                                       g_wszDllPath,
                                       pszOverrideFuncName);

    if (g_bRegStatus) {
        g_bRegStatus = bStatus;
    }

    bStatus ? wprintf_s(L"OK.\n") : wprintf_s(L"Failed.\n");
    return bStatus;
}

void Register(void) {
    PCERTUIEXTS_REG_INFO pRegInfo;

    for (DWORD i = 0; i < g_cRegInfo; i++) {
        pRegInfo = &g_rgRegInfo[i];

        RegisterOIDInfo(pRegInfo->pszOID, pRegInfo->pwszName, pRegInfo->dwGroupId);
        if (pRegInfo->pszFuncName != NULL) {
            RegisterOIDFunction(pRegInfo->pszOID,
                                pRegInfo->pwszName,
                                pRegInfo->pszFuncName,
                                pRegInfo->pszOverrideFuncName);
        }
    }
}

#pragma endregion

#pragma region Uninstall

BOOL UnregisterOIDInfo(_In_z_ const PSTR pszOID,
                       _In_z_ const PWSTR pwszName,
                       _In_ const DWORD dwGroupId) {
    BOOL bStatus = FALSE;
    PCRYPT_OID_INFO pOIDInfo;

    wprintf_s(L"[%s] Unregistering OID info ... ", pwszName);

    pOIDInfo = malloc(sizeof(CRYPT_OID_INFO));
    if (pOIDInfo == NULL) {
        goto end;
    }

    memset(pOIDInfo, 0, sizeof(CRYPT_OID_INFO));

    pOIDInfo->cbSize = sizeof(CRYPT_OID_INFO);
    pOIDInfo->pszOID = pszOID;
    pOIDInfo->dwGroupId = dwGroupId;

    bStatus = CryptUnregisterOIDInfo(pOIDInfo);
    free(pOIDInfo);

end:
    if (g_bRegStatus) {
        g_bRegStatus = bStatus;
    }

    bStatus ? wprintf_s(L"OK.\n") : wprintf_s(L"Failed.\n");
    return bStatus;
}

BOOL UnregisterOIDFunction(_In_z_ const PSTR pszOID,
                           _In_z_ const PWSTR pwszName,
                           _In_z_ const PSTR pszFuncName) {
    BOOL bStatus;

    wprintf_s(L"[%s] Unregistering OID function ... ", pwszName);

    bStatus = CryptUnregisterOIDFunction(X509_ASN_ENCODING,
                                         pszFuncName,
                                         pszOID);

    if (g_bRegStatus) {
        g_bRegStatus = bStatus;
    }

    bStatus ? wprintf_s(L"OK.\n") : wprintf_s(L"Failed.\n");
    return bStatus;
}

void Unregister(void) {
    PCERTUIEXTS_REG_INFO pRegInfo;

    for (DWORD i = 0; i < g_cRegInfo; i++) {
        pRegInfo = &g_rgRegInfo[i];

        UnregisterOIDInfo(pRegInfo->pszOID, pRegInfo->pwszName, pRegInfo->dwGroupId);
        if (pRegInfo->pszFuncName != NULL) {
            UnregisterOIDFunction(pRegInfo->pszOID, pRegInfo->pwszName, pRegInfo->pszFuncName);
        }
    }
}

#pragma endregion

int main(_In_ const int argc,
         _In_reads_(argc) const char* argv[]) {
    LONG status = 1;

    switch (argc) {
        case 2:
            break;
        case 1:
            status = 0;
        default: // NOLINT(clang-diagnostic-implicit-fallthrough)
            DisplayHelp(status);
            goto end;
    }

    if (_stricmp(argv[1], "/i") == 0) {
        if (!GetDllPath()) {
            goto end;
        }

        Register();
        if (g_bRegStatus) {
            status = 0;
        }
    } else if (_stricmp(argv[1], "/u") == 0) {
        Unregister();
        if (g_bRegStatus) {
            status = 0;
        }
    } else if (_stricmp(argv[1], "/?") == 0 || _stricmp(argv[1], "/h") == 0) {
        DisplayHelp(FALSE);
        status = 0;
    } else {
        DisplayHelp(TRUE);
    }

end:
    return status;
}
