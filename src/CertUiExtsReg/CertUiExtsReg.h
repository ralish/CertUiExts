#pragma once

// String constants (ASCII)
#define szCRYPT_FORMAT_OBJECT "CryptDllFormatObject"

// String constants (Unicode)
#define wszDLL_NAME L"CertUiExts.dll"
#define wszEXE_NAME L"CertUiExtsReg.exe"

// Registration information
typedef struct _CERTUIEXTS_REG_INFO {
    PSTR pszOID;
    PWSTR pwszName;
    PWSTR pwszRegName;
    DWORD dwGroupId;
    PSTR pszFuncName;
    PSTR pszOverrideFuncName;
} CERTUIEXTS_REG_INFO, *PCERTUIEXTS_REG_INFO;

// Array of OIDs and functions to register
CERTUIEXTS_REG_INFO g_rgRegInfo[] = {
    /*
     * CA/Browser Forum
     * 2.23.140
     */
    {
        // certificate-policies(1) -> ev-guidelines(1)
        "2.23.140.1.1",
        L"CA/Browser Forum: Extended Validation (EV) TLS Certificate",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> baseline-requirements(2) -> domain-validated(1)
        "2.23.140.1.2.1",
        L"CA/Browser Forum: Domain Validated (DV) TLS Certificate",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> baseline-requirements(2) -> organization-validated(2)
        "2.23.140.1.2.2",
        L"CA/Browser Forum: Organization Validated (OV) TLS Certificate",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> baseline-requirements(2) -> individual-validated(3)
        "2.23.140.1.2.3",
        L"CA/Browser Forum: Individual Validated (IV) TLS Certificate",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> extended-validation-codesigning(3)
        "2.23.140.1.3",
        L"CA/Browser Forum: Extended Validation (EV) Code Signing Certificate",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> code-signing-requirements(4) -> code-signing(1)
        "2.23.140.1.4.1",
        L"CA/Browser Forum: Code Signing Certificate",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> code-signing-requirements(4) -> timestamping(2)
        "2.23.140.1.4.2",
        L"CA/Browser Forum: Timestamping Certificate",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> smime-baseline(5) -> mailbox-validated(1) -> legacy(1)
        "2.23.140.1.5.1.1",
        L"CA/Browser Forum: Mailbox Validated S/MIME Certificate (Legacy)",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> smime-baseline(5) -> mailbox-validated(1) -> multipurpose(2)
        "2.23.140.1.5.1.2",
        L"CA/Browser Forum: Mailbox Validated S/MIME Certificate (Multipurpose)",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> smime-baseline(5) -> mailbox-validated(1) -> strict(3)
        "2.23.140.1.5.1.3",
        L"CA/Browser Forum: Mailbox Validated S/MIME Certificate (Strict)",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> smime-baseline(5) -> organization-validated(2) -> legacy(1)
        "2.23.140.1.5.2.1",
        L"CA/Browser Forum: Organization Validated S/MIME Certificate (Legacy)",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> smime-baseline(5) -> organization-validated(2) -> multipurpose(2)
        "2.23.140.1.5.2.2",
        L"CA/Browser Forum: Organization Validated S/MIME Certificate (Multipurpose)",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> smime-baseline(5) -> organization-validated(2) -> strict(3)
        "2.23.140.1.5.2.3",
        L"CA/Browser Forum: Organization Validated S/MIME Certificate (Strict)",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> smime-baseline(5) -> sponsor-validated(3) -> legacy(1)
        "2.23.140.1.5.3.1",
        L"CA/Browser Forum: Sponsor Validated S/MIME Certificate (Legacy)",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> smime-baseline(5) -> sponsor-validated(3) -> multipurpose(2)
        "2.23.140.1.5.3.2",
        L"CA/Browser Forum: Sponsor Validated S/MIME Certificate (Multipurpose)",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> smime-baseline(5) -> sponsor-validated(3) -> strict(3)
        "2.23.140.1.5.3.3",
        L"CA/Browser Forum: Sponsor Validated S/MIME Certificate (Strict)",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> smime-baseline(5) -> individual-validated(4) -> legacy(1)
        "2.23.140.1.5.4.1",
        L"CA/Browser Forum: Individual Validated S/MIME Certificate (Legacy)",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> smime-baseline(5) -> individual-validated(4) -> multipurpose(2)
        "2.23.140.1.5.4.2",
        L"CA/Browser Forum: Individual Validated S/MIME Certificate (Multipurpose)",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> smime-baseline(5) -> individual-validated(4) -> strict(3)
        "2.23.140.1.5.4.3",
        L"CA/Browser Forum: Individual Validated S/MIME Certificate (Strict)",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },

    /*
     * DigiCert
     * 2.16.840.1.114412
     */
    {
        "2.16.840.1.114412.1.1",
        L"DigiCert: Organization Validated (OV) TLS Certificate",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "2.16.840.1.114412.1.2",
        L"DigiCert: Domain Validated (DV) TLS Certificate",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "2.16.840.1.114412.2.1",
        L"DigiCert: Extended Validation (EV) TLS Certificate",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "2.16.840.1.114412.3.1.1",
        L"DigiCert: Code Signing Certificate",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "2.16.840.1.114412.3.2",
        L"DigiCert: Extended Validation (EV) Code Signing Certificate",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "2.16.840.1.114412.3.11",
        L"DigiCert: Windows Kernel Driver Code Signing Certificate",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "2.16.840.1.114412.7.1",
        L"DigiCert: Timestamping Certificate",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },

    /*
     * Microsoft: Active Directory
     * 1.3.6.1.4.1.311.25
     */
    {
        "1.3.6.1.4.1.311.25.2",
        L"AD DS: CA Security",
        L"Microsoft: Active Directory - CA Security",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        szCRYPT_FORMAT_OBJECT,
        "FormatNtdsCaSecurityExt"
    },
    {
        "1.3.6.1.4.1.311.25.2.1",
        L"AD DS: Object SID",
        L"Microsoft: Active Directory - Object SID",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        NULL,
        NULL
    },

    /*
     * Microsoft: ASP.NET Core
     * 1.3.6.1.4.1.311.84
     */
    {
        "1.3.6.1.4.1.311.84.1.1",
        L"ASP.NET Core: HTTPS Development Certificate",
        L"Microsoft: ASP.NET Core - HTTPS Development Certificate",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        szCRYPT_FORMAT_OBJECT,
        "FormatAspNetCoreHttpsDevCert"
    },

    /*
     * Microsoft: Authenticode
     * 1.3.6.1.4.1.311.2
     */
    {
        "1.3.6.1.4.1.311.2.1.11",
        L"Statement Type",
        L"Microsoft: Authenticode - SPC Statement Type",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        szCRYPT_FORMAT_OBJECT,
        "FormatAuthenticodeSpcStatementType"
    },
    {
        "1.3.6.1.4.1.311.2.1.12",
        L"Publisher Info",
        L"Microsoft: Authenticode - SPC Publisher Information",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        szCRYPT_FORMAT_OBJECT,
        "FormatAuthenticodeSpcPublisherInfo"
    },

    /*
     * Microsoft: Entra ID
     * 1.2.840.113556.1.5.284
     */
    {
        "1.2.840.113556.1.5.284.1",
        L"Entra ID: NTDS-DSA Invocation ID",
        L"Microsoft: Entra ID - NTDS-DSA Invocation ID",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        szCRYPT_FORMAT_OBJECT,
        "FormatEntraIdNtdsDsaInvId"
    },
    {
        "1.2.840.113556.1.5.284.2",
        L"Entra ID: Device ID",
        L"Microsoft: Entra ID - Device ID",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        szCRYPT_FORMAT_OBJECT,
        "FormatEntraIdDeviceId"
    },
    {
        "1.2.840.113556.1.5.284.3",
        L"Entra ID: User ID",
        L"Microsoft: Entra ID - User ID",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        szCRYPT_FORMAT_OBJECT,
        "FormatEntraIdUserId"
    },
    {
        "1.2.840.113556.1.5.284.4",
        L"Entra ID: Domain ID",
        L"Microsoft: Entra ID - Domain ID",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        szCRYPT_FORMAT_OBJECT,
        "FormatEntraIdDomainId"
    },
    {
        "1.2.840.113556.1.5.284.5",
        L"Entra ID: Tenant ID",
        L"Microsoft: Entra ID - Tenant ID",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        szCRYPT_FORMAT_OBJECT,
        "FormatEntraIdTenantId"
    },
    {
        "1.2.840.113556.1.5.284.7",
        L"Entra ID: Join Type",
        L"Microsoft: Entra ID - Join Type",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        szCRYPT_FORMAT_OBJECT,
        "FormatEntraIdJoinType"
    },
    {
        "1.2.840.113556.1.5.284.8",
        L"Entra ID: Tenant Region",
        L"Microsoft: Entra ID - Tenant Region",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        szCRYPT_FORMAT_OBJECT,
        "FormatEntraIdTenantRegion"
    },

    /*
     * Microsoft: Intune
     * 1.2.840.113556.5
     */
    {
        "1.2.840.113556.5.4",
        L"Intune: Device ID",
        L"Microsoft: Intune - Device ID",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        szCRYPT_FORMAT_OBJECT,
        "FormatIntuneDeviceId"
    },
    {
        "1.2.840.113556.5.6",
        L"Intune: Account ID",
        L"Microsoft: Intune - Account ID",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        szCRYPT_FORMAT_OBJECT,
        "FormatIntuneAccountId"
    },
    {
        "1.2.840.113556.5.10",
        L"Intune: User ID",
        L"Microsoft: Intune - User ID",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        szCRYPT_FORMAT_OBJECT,
        "FormatIntuneUserId"
    },
#ifdef _DEBUG
    {
        "1.2.840.113556.5.11",
        L"Intune: Unknown (11)",
        L"Microsoft: Intune - Unknown (11)",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        szCRYPT_FORMAT_OBJECT,
        "FormatIntuneUnknown11"
    },
#endif
    {
        "1.2.840.113556.5.14",
        L"Intune: Entra ID Tenant ID",
        L"Microsoft: Intune - Entra ID Tenant ID",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        szCRYPT_FORMAT_OBJECT,
        "FormatIntuneEntraIdTenantId"
    },

    /*
     * Microsoft: Time Stamping
     * 1.3.6.1.4.1.311.3
     */
    {
        "1.3.6.1.4.1.311.3.3.1",
        L"Timestamp Signature",
        L"Microsoft: Timestamping - Timestamping Signature",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        NULL,
        NULL
    },

    /*
     * Sectigo
     * 1.3.6.1.4.1.6449
     */
    {
        // Personal Secure Email
        "1.3.6.1.4.1.6449.1.2.1.1.1",
        L"Sectigo: S/MIME Certificate (Class 1)",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // Secure Server
        "1.3.6.1.4.1.6449.1.2.1.3.1",
        L"Sectigo: TLS Certificate",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // Software Publisher
        "1.3.6.1.4.1.6449.1.2.1.3.2",
        L"Sectigo: Code Signing Certificate",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // InstantSSL
        "1.3.6.1.4.1.6449.1.2.1.3.4",
        L"Sectigo: Organization Validated (OV) TLS Certificate",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // Corporate Secure Email
        "1.3.6.1.4.1.6449.1.2.1.3.5",
        L"Sectigo: S/MIME Certificate (Class 2)",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // Enterprise-Wide Secure Email
        "1.3.6.1.4.1.6449.1.2.1.3.6",
        L"Sectigo: S/MIME Certificate (Class 3)",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "1.3.6.1.4.1.6449.1.2.1.3.8",
        L"Sectigo: Timestamping Certificate",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "1.3.6.1.4.1.6449.1.2.1.5.1",
        L"Sectigo: Extended Validation (EV) TLS Certificate",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "1.3.6.1.4.1.6449.1.2.1.6.1",
        L"Sectigo: Extended Validation (EV) Code Signing Certificate",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "1.3.6.1.4.1.6449.1.2.1.6.6",
        L"Sectigo: Document Signing (local)",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "1.3.6.1.4.1.6449.1.2.1.6.7",
        L"Sectigo: Document Signing (remote)",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "1.3.6.1.4.1.6449.1.2.1.6.8",
        L"Sectigo: Document Signing (external trusted partner)",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // DV Secure Server
        "1.3.6.1.4.1.6449.1.2.2.7",
        L"Sectigo: Domain Validated (DV) TLS Certificate",
        NULL,
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
};

// Number of registration information elements
DWORD g_cRegInfo = sizeof(g_rgRegInfo) / sizeof(CERTUIEXTS_REG_INFO);
