#include "pch.h"

#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>

#include <windows.h>
#include <shlwapi.h>
#include <wincrypt.h>

#include "OIDs.h"

#include "CertUiExtsReg.h"

// Set to false if any (un)registration returns false
BOOL g_bRegStatus = TRUE;

// DLL path used in OID info & function registrations
WCHAR g_pwszDllPath[MAX_PATH * sizeof(WCHAR)];

void DisplayHelp(BOOL bInvalidParam)
{
    if (bInvalidParam) {
        wprintf_s(L"An invalid parameter was provided.\n\n");
    }

    wprintf_s(L"Certificate UI Extensions\n\n");
    wprintf_s(L"Usage: %s [/i | /u]\n", wszEXE_NAME);
    wprintf_s(L"  /i    Register the extension\n");
    wprintf_s(L"  /u    Unregister the extension");
}

BOOL GetDllPath(void)
{
    BOOL  bStatus = FALSE;
    DWORD dwPathLen;

    dwPathLen = GetModuleFileNameW(NULL, g_pwszDllPath, MAX_PATH * sizeof(WCHAR));
    if (dwPathLen == 0) {
        wprintf_s(L"Retrieving executable path failed (err: %d)", GetLastError());
        goto end;
    }

    if (dwPathLen >= MAX_PATH * sizeof(WCHAR)) {
        wprintf_s(L"Retrieved executable path exceeded MAX_SIZE.");
        goto end;
    }

    if (!PathRemoveFileSpecW(g_pwszDllPath)) {
        wprintf_s(L"Failed to remove file from executable path.");
        goto end;
    }

    if (PathCombineW(g_pwszDllPath, g_pwszDllPath, wszDLL_NAME) == NULL) {
        wprintf_s(L"Failed to combine directory path with DLL file.");
        goto end;
    }

    bStatus = TRUE;

end:
    return bStatus;
}

#pragma region Install

BOOL RegisterOIDInfo(const LPSTR  pszOID,
                     const LPWSTR pwszName,
                     const DWORD  dwGroupId)
{
    BOOL            bStatus = FALSE;
    CRYPT_OID_INFO* pOIDInfo;

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

BOOL RegisterOIDFunction(const LPSTR  pszOID,
                         const LPWSTR pwszName,
                         const LPSTR  pszFuncName,
                         const LPSTR  pszOverrideFuncName)
{
    BOOL bStatus;

    wprintf_s(L"[%s] Registering OID function ... ", pwszName);

    bStatus = CryptRegisterOIDFunction(X509_ASN_ENCODING,
                                       pszFuncName,
                                       pszOID,
                                       g_pwszDllPath,
                                       pszOverrideFuncName);

    if (g_bRegStatus) {
        g_bRegStatus = bStatus;
    }

    bStatus ? wprintf_s(L"OK.\n") : wprintf_s(L"Failed.\n");
    return bStatus;
}

void Register(void)
{
    /*
     * Type: Active Directory Domain Services
     * OIDs: 1.3.6.1.4.1.311.25.*
     */

    RegisterOIDInfo(szNTDS_CA_SECURITY_EXT_OID, wszNTDS_CA_SECURITY_EXT_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    RegisterOIDFunction(szNTDS_CA_SECURITY_EXT_OID, wszNTDS_CA_SECURITY_EXT_NAME,
                        szCRYPT_FORMAT_OBJECT, "FormatNtdsCaSecurityExt");


    /*
     * Type: Azure AD
     * OIDs: 1.2.840.113556.1.5.284.x
     */

    RegisterOIDInfo(szAAD_NTDS_DSA_IID_OID, wszAAD_NTDS_DSA_IID_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    RegisterOIDFunction(szAAD_NTDS_DSA_IID_OID, wszAAD_NTDS_DSA_IID_NAME,
                        szCRYPT_FORMAT_OBJECT, "FormatAadNtdsDsaIid");

    RegisterOIDInfo(szAAD_DEVICE_ID_OID, wszAAD_DEVICE_ID_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    RegisterOIDFunction(szAAD_DEVICE_ID_OID, wszAAD_DEVICE_ID_NAME,
                        szCRYPT_FORMAT_OBJECT, "FormatAadDeviceId");

    RegisterOIDInfo(szAAD_USER_ID_OID, wszAAD_USER_ID_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    RegisterOIDFunction(szAAD_USER_ID_OID, wszAAD_USER_ID_NAME,
                        szCRYPT_FORMAT_OBJECT, "FormatAadUserId");

    RegisterOIDInfo(szAAD_DOMAIN_ID_OID, wszAAD_DOMAIN_ID_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    RegisterOIDFunction(szAAD_DOMAIN_ID_OID, wszAAD_DOMAIN_ID_NAME,
                        szCRYPT_FORMAT_OBJECT, "FormatAadDomainId");

    RegisterOIDInfo(szAAD_TENANT_ID_OID, wszAAD_TENANT_ID_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    RegisterOIDFunction(szAAD_TENANT_ID_OID, wszAAD_TENANT_ID_NAME,
                        szCRYPT_FORMAT_OBJECT, "FormatAadTenantId");

    RegisterOIDInfo(szAAD_JOIN_TYPE_OID, wszAAD_JOIN_TYPE_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    RegisterOIDFunction(szAAD_JOIN_TYPE_OID, wszAAD_JOIN_TYPE_NAME,
                        szCRYPT_FORMAT_OBJECT, "FormatAadJoinType");

    RegisterOIDInfo(szAAD_TENANT_REGION_OID, wszAAD_TENANT_REGION_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    RegisterOIDFunction(szAAD_TENANT_REGION_OID, wszAAD_TENANT_REGION_NAME,
                        szCRYPT_FORMAT_OBJECT, "FormatAadTenantRegion");


    /*
     * Type: Intune
     * OIDs: 1.2.840.113556.5.*
     */

    RegisterOIDInfo(szINTUNE_DEVICE_ID_OID, wszINTUNE_DEVICE_ID_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    RegisterOIDFunction(szINTUNE_DEVICE_ID_OID, wszINTUNE_DEVICE_ID_NAME,
                        szCRYPT_FORMAT_OBJECT, "FormatIntuneDeviceId");

    RegisterOIDInfo(szINTUNE_ACCOUNT_ID_OID, wszINTUNE_ACCOUNT_ID_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    RegisterOIDFunction(szINTUNE_ACCOUNT_ID_OID, wszINTUNE_ACCOUNT_ID_NAME,
                        szCRYPT_FORMAT_OBJECT, "FormatIntuneAccountId");

    RegisterOIDInfo(szINTUNE_USER_ID_OID, wszINTUNE_USER_ID_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    RegisterOIDFunction(szINTUNE_USER_ID_OID, wszINTUNE_USER_ID_NAME,
                        szCRYPT_FORMAT_OBJECT, "FormatIntuneUserId");

#ifdef _DEBUG
    RegisterOIDInfo(szINTUNE_UNKNOWN_11_OID, wszINTUNE_UNKNOWN_11_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    RegisterOIDFunction(szINTUNE_UNKNOWN_11_OID, wszINTUNE_UNKNOWN_11_NAME,
                        szCRYPT_FORMAT_OBJECT, "FormatIntuneUnknown11");
#endif

    RegisterOIDInfo(szINTUNE_AAD_TENANT_ID_OID, wszINTUNE_AAD_TENANT_ID_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    RegisterOIDFunction(szINTUNE_AAD_TENANT_ID_OID, wszINTUNE_AAD_TENANT_ID_NAME,
                        szCRYPT_FORMAT_OBJECT, "FormatIntuneAadTenantId");
}

#pragma endregion

#pragma region Uninstall

BOOL UnregisterOIDInfo(const LPSTR  pszOID,
                       const LPWSTR pwszName,
                       const DWORD  dwGroupId)
{
    BOOL            bStatus = FALSE;
    CRYPT_OID_INFO* pOIDInfo;

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

BOOL UnregisterOIDFunction(const LPSTR  pszOID,
                           const LPWSTR pwszName,
                           const LPSTR  pszFuncName)
{
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

void Unregister(void)
{
    /*
     * Type: Active Directory Domain Services
     * OIDs: 1.3.6.1.4.1.311.25.*
     */

    UnregisterOIDInfo(szNTDS_CA_SECURITY_EXT_OID, wszNTDS_CA_SECURITY_EXT_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    UnregisterOIDFunction(szNTDS_CA_SECURITY_EXT_OID, wszNTDS_CA_SECURITY_EXT_NAME, szCRYPT_FORMAT_OBJECT);


    /*
     * Type: Azure AD
     * OIDs: 1.2.840.113556.1.5.284.x
     */

    UnregisterOIDInfo(szAAD_NTDS_DSA_IID_OID, wszAAD_NTDS_DSA_IID_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    UnregisterOIDFunction(szAAD_NTDS_DSA_IID_OID, wszAAD_NTDS_DSA_IID_NAME, szCRYPT_FORMAT_OBJECT);

    UnregisterOIDInfo(szAAD_DEVICE_ID_OID, wszAAD_DEVICE_ID_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    UnregisterOIDFunction(szAAD_DEVICE_ID_OID, wszAAD_DEVICE_ID_NAME, szCRYPT_FORMAT_OBJECT);

    UnregisterOIDInfo(szAAD_USER_ID_OID, wszAAD_USER_ID_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    UnregisterOIDFunction(szAAD_USER_ID_OID, wszAAD_USER_ID_NAME, szCRYPT_FORMAT_OBJECT);

    UnregisterOIDInfo(szAAD_DOMAIN_ID_OID, wszAAD_DOMAIN_ID_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    UnregisterOIDFunction(szAAD_DOMAIN_ID_OID, wszAAD_DOMAIN_ID_NAME, szCRYPT_FORMAT_OBJECT);

    UnregisterOIDInfo(szAAD_TENANT_ID_OID, wszAAD_TENANT_ID_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    UnregisterOIDFunction(szAAD_TENANT_ID_OID, wszAAD_TENANT_ID_NAME, szCRYPT_FORMAT_OBJECT);

    UnregisterOIDInfo(szAAD_JOIN_TYPE_OID, wszAAD_JOIN_TYPE_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    UnregisterOIDFunction(szAAD_JOIN_TYPE_OID, wszAAD_JOIN_TYPE_NAME, szCRYPT_FORMAT_OBJECT);

    UnregisterOIDInfo(szAAD_TENANT_REGION_OID, wszAAD_TENANT_REGION_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    UnregisterOIDFunction(szAAD_TENANT_REGION_OID, wszAAD_TENANT_REGION_NAME, szCRYPT_FORMAT_OBJECT);


    /*
     * Type: Intune
     * OIDs: 1.2.840.113556.5.*
     */

    UnregisterOIDInfo(szINTUNE_DEVICE_ID_OID, wszINTUNE_DEVICE_ID_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    UnregisterOIDFunction(szINTUNE_DEVICE_ID_OID, wszINTUNE_DEVICE_ID_NAME, szCRYPT_FORMAT_OBJECT);

    UnregisterOIDInfo(szINTUNE_ACCOUNT_ID_OID, wszINTUNE_ACCOUNT_ID_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    UnregisterOIDFunction(szINTUNE_ACCOUNT_ID_OID, wszINTUNE_ACCOUNT_ID_NAME, szCRYPT_FORMAT_OBJECT);

    UnregisterOIDInfo(szINTUNE_USER_ID_OID, wszINTUNE_USER_ID_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    UnregisterOIDFunction(szINTUNE_USER_ID_OID, wszINTUNE_USER_ID_NAME, szCRYPT_FORMAT_OBJECT);

#ifdef _DEBUG
    UnregisterOIDInfo(szINTUNE_UNKNOWN_11_OID, wszINTUNE_UNKNOWN_11_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    UnregisterOIDFunction(szINTUNE_UNKNOWN_11_OID, wszINTUNE_UNKNOWN_11_NAME, szCRYPT_FORMAT_OBJECT);
#endif

    UnregisterOIDInfo(szINTUNE_AAD_TENANT_ID_OID, wszINTUNE_AAD_TENANT_ID_NAME, CRYPT_EXT_OR_ATTR_OID_GROUP_ID);
    UnregisterOIDFunction(szINTUNE_AAD_TENANT_ID_OID, wszINTUNE_AAD_TENANT_ID_NAME, szCRYPT_FORMAT_OBJECT);
}

#pragma endregion

int main(int argc, char* argv[])
{
    LONG status = 1;

    switch (argc) {
        case 2:
            break;
        case 1:
            status = 0;
        default:
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
