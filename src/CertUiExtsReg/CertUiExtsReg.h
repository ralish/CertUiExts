#pragma once

// String constants (ASCII)
#define CRYPT_FORMAT_OBJECT_A "CryptDllFormatObject"

// String constants (Unicode)
#define DLL_NAME_W L"CertUiExts.dll"
#define EXE_NAME_W L"CertUiExtsReg.exe"

// Registration information
typedef struct _CERTUIEXTS_REG_INFO {
    /*
     * The OID being (un)registered.
     */
    PSTR pszOID;

    /*
     * The display name associated with the OID.
     */
    PWSTR pwszName;

    /*
     * Optional OID name output by CertUiExtsReg when (un)registering the OID.
     * If not provided, will default to the value of the pwszName field. The
     * value of this field is not passed to any Windows cryptography APIs.
     */
    PWSTR pwszRegName;

    /*
     * One of the identifiers documented for the dwGroupId field of the
     * CRYPT_OID_INFO structure. Specifies the group the OID belongs to.
     */
    DWORD dwGroupId;

    /*
     * Optional name of the cryptographic function which when called to decode
     * the OID should instead invoke the function of the same name exported
     * from this library. If NULL, calling CryptRegisterOIDFunction(...) will
     * be skipped when registering the OID (and equivalent when unregistering).
     */
    PSTR pszFuncName;

    /*
     * When pszFuncName is set, overrides the name of the exported function to
     * be called. This allows implementing multiple different decoders in the
     * same library without having to implement our own dispatcher.
     */
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
        L"CA/Browser Forum Extended Validation (EV) TLS Certificate",
        L"CA/Browser Forum: Extended Validation (EV) TLS Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> baseline-requirements(2) -> domain-validated(1)
        "2.23.140.1.2.1",
        L"CA/Browser Forum Domain Validated (DV) TLS Certificate",
        L"CA/Browser Forum: Domain Validated (DV) TLS Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> baseline-requirements(2) -> organization-validated(2)
        "2.23.140.1.2.2",
        L"CA/Browser Forum Organization Validated (OV) TLS Certificate",
        L"CA/Browser Forum: Organization Validated (OV) TLS Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> baseline-requirements(2) -> individual-validated(3)
        "2.23.140.1.2.3",
        L"CA/Browser Forum Individual Validated (IV) TLS Certificate",
        L"CA/Browser Forum: Individual Validated (IV) TLS Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> extended-validation-codesigning(3)
        "2.23.140.1.3",
        L"CA/Browser Forum Extended Validation (EV) Code Signing Certificate",
        L"CA/Browser Forum: Extended Validation (EV) Code Signing Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> code-signing-requirements(4) -> code-signing(1)
        "2.23.140.1.4.1",
        L"CA/Browser Forum Code Signing Certificate",
        L"CA/Browser Forum: Code Signing Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> code-signing-requirements(4) -> timestamping(2)
        "2.23.140.1.4.2",
        L"CA/Browser Forum Timestamping Certificate",
        L"CA/Browser Forum: Timestamping Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> smime-baseline(5) -> mailbox-validated(1) -> legacy(1)
        "2.23.140.1.5.1.1",
        L"CA/Browser Forum Mailbox Validated S/MIME Certificate (Legacy)",
        L"CA/Browser Forum: Mailbox Validated S/MIME Certificate (Legacy) Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> smime-baseline(5) -> mailbox-validated(1) -> multipurpose(2)
        "2.23.140.1.5.1.2",
        L"CA/Browser Forum Mailbox Validated S/MIME Certificate (Multipurpose)",
        L"CA/Browser Forum: Mailbox Validated S/MIME Certificate (Multipurpose) Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> smime-baseline(5) -> mailbox-validated(1) -> strict(3)
        "2.23.140.1.5.1.3",
        L"CA/Browser Forum Mailbox Validated S/MIME Certificate (Strict)",
        L"CA/Browser Forum: Mailbox Validated S/MIME Certificate (Strict) Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> smime-baseline(5) -> organization-validated(2) -> legacy(1)
        "2.23.140.1.5.2.1",
        L"CA/Browser Forum Organization Validated S/MIME Certificate (Legacy)",
        L"CA/Browser Forum: Organization Validated S/MIME Certificate (Legacy) Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> smime-baseline(5) -> organization-validated(2) -> multipurpose(2)
        "2.23.140.1.5.2.2",
        L"CA/Browser Forum Organization Validated S/MIME Certificate (Multipurpose)",
        L"CA/Browser Forum: Organization Validated S/MIME Certificate (Multipurpose) Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> smime-baseline(5) -> organization-validated(2) -> strict(3)
        "2.23.140.1.5.2.3",
        L"CA/Browser Forum Organization Validated S/MIME Certificate (Strict)",
        L"CA/Browser Forum: Organization Validated S/MIME Certificate (Strict) Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> smime-baseline(5) -> sponsor-validated(3) -> legacy(1)
        "2.23.140.1.5.3.1",
        L"CA/Browser Forum Sponsor Validated S/MIME Certificate (Legacy)",
        L"CA/Browser Forum: Sponsor Validated S/MIME Certificate (Legacy) Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> smime-baseline(5) -> sponsor-validated(3) -> multipurpose(2)
        "2.23.140.1.5.3.2",
        L"CA/Browser Forum Sponsor Validated S/MIME Certificate (Multipurpose)",
        L"CA/Browser Forum: Sponsor Validated S/MIME Certificate (Multipurpose) Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> smime-baseline(5) -> sponsor-validated(3) -> strict(3)
        "2.23.140.1.5.3.3",
        L"CA/Browser Forum Sponsor Validated S/MIME Certificate (Strict)",
        L"CA/Browser Forum: Sponsor Validated S/MIME Certificate (Strict) Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> smime-baseline(5) -> individual-validated(4) -> legacy(1)
        "2.23.140.1.5.4.1",
        L"CA/Browser Forum Individual Validated S/MIME Certificate (Legacy)",
        L"CA/Browser Forum: Individual Validated S/MIME Certificate (Legacy) Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> smime-baseline(5) -> individual-validated(4) -> multipurpose(2)
        "2.23.140.1.5.4.2",
        L"CA/Browser Forum Individual Validated S/MIME Certificate (Multipurpose)",
        L"CA/Browser Forum: Individual Validated S/MIME Certificate (Multipurpose) Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // certificate-policies(1) -> smime-baseline(5) -> individual-validated(4) -> strict(3)
        "2.23.140.1.5.4.3",
        L"CA/Browser Forum Individual Validated S/MIME Certificate (Strict)",
        L"CA/Browser Forum: Individual Validated S/MIME Certificate (Strict) Policy",
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
        L"DigiCert Organization Validated (OV) TLS Certificate",
        L"DigiCert: Organization Validated (OV) TLS Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "2.16.840.1.114412.1.2",
        L"DigiCert Domain Validated (DV) TLS Certificate",
        L"DigiCert: Domain Validated (DV) TLS Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "2.16.840.1.114412.2.1",
        L"DigiCert Extended Validation (EV) TLS Certificate",
        L"DigiCert: Extended Validation (EV) TLS Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "2.16.840.1.114412.3.1.1",
        L"DigiCert Code Signing Certificate",
        L"DigiCert: Code Signing Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "2.16.840.1.114412.3.2",
        L"DigiCert Extended Validation (EV) Code Signing Certificate",
        L"DigiCert: Extended Validation (EV) Code Signing Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "2.16.840.1.114412.3.11",
        L"DigiCert Windows Kernel Driver Code Signing Certificate",
        L"DigiCert: Windows Kernel Driver Code Signing Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "2.16.840.1.114412.7.1",
        L"DigiCert Timestamping Certificate",
        L"DigiCert: Timestamping Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },

    /*
     * Entrust
     * 2.16.840.1.114028
     */
    {
        "2.16.840.1.114028.10.1.2",
        L"Entrust Extended Validation (EV) SSL or Code Signing Certificate",
        L"Entrust: Extended Validation (EV) SSL or Code Signing Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "2.16.840.1.114028.10.1.3",
        L"Entrust Code Signing Certificate",
        L"Entrust: Code Signing Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "2.16.840.1.114028.10.1.4.1",
        L"Entrust Client Certificate (Class 1)",
        L"Entrust: Client Certificate (Class 1) Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "2.16.840.1.114028.10.1.4.2",
        L"Entrust Client Certificate (Class 2)",
        L"Entrust: Client Certificate (Class 2) Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "2.16.840.1.114028.10.1.5",
        L"Entrust SSL Certificate",
        L"Entrust: SSL Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "2.16.840.1.114028.10.1.6",
        L"Entrust Document Signing Certificate",
        L"Entrust: Document Signing Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "2.16.840.1.114028.10.1.7",
        L"Entrust Timestamping Certificate",
        L"Entrust: Timestamping Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "2.16.840.1.114028.10.1.11",
        L"Entrust Verified Mark Certificate",
        L"Entrust: Verified Mark Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "2.16.840.1.114028.10.3.5",
        L"Entrust Timestamping Certificate",
        L"Entrust: Timestamping Certificate Policy",
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
        CRYPT_FORMAT_OBJECT_A,
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
        CRYPT_FORMAT_OBJECT_A,
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
        CRYPT_FORMAT_OBJECT_A,
        "FormatAuthenticodeSpcStatementType"
    },
    {
        "1.3.6.1.4.1.311.2.1.12",
        L"Publisher Info",
        L"Microsoft: Authenticode - SPC Publisher Information",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        CRYPT_FORMAT_OBJECT_A,
        "FormatAuthenticodeSpcPublisherInfo"
    },

    /*
     * Microsoft: Certificate Services
     * 1.3.6.1.4.1.311.21
     */
    {
        "1.3.6.1.4.1.311.21.36",
        L"Microsoft Privacy CA encryption",
        L"Microsoft: Certificate Services - Privacy CA encryption",
        CRYPT_ENHKEY_USAGE_OID_GROUP_ID,
        NULL,
        NULL
    },

    /*
     * Microsoft: Defender for Endpoint
     * 1.3.6.1.4.1.311.126
     */
#ifdef _DEBUG
    {
        "1.3.6.1.4.1.311.126.4",
        L"Defender for Endpoint: Unknown (4)",
        L"Microsoft: Defender for Endpoint - Unknown (4)",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        CRYPT_FORMAT_OBJECT_A,
        "FormatGenericAsnGuid"
    },
#endif
    {
        "1.3.6.1.4.1.311.126.6",
        L"Defender for Endpoint: Entra ID Tenant ID",
        L"Microsoft: Defender for Endpoint - Entra ID Tenant ID",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        CRYPT_FORMAT_OBJECT_A,
        "FormatGenericAsnGuid"
    },
#ifdef _DEBUG
    {
        "1.3.6.1.4.1.311.126.15",
        L"Defender for Endpoint: Unknown (15)",
        L"Microsoft: Defender for Endpoint - Unknown (15)",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        CRYPT_FORMAT_OBJECT_A,
        "FormatGenericAsnInteger"
    },
    {
        "1.3.6.1.4.1.311.126.17",
        L"Defender for Endpoint: Unknown (17)",
        L"Microsoft: Defender for Endpoint - Unknown (17)",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        CRYPT_FORMAT_OBJECT_A,
        "FormatGenericAsnInteger"
    },
#endif
    {
        "1.3.6.1.4.1.311.126.20",
        L"Defender for Endpoint: Entra ID Device ID",
        L"Microsoft: Defender for Endpoint - Entra ID Device ID",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        CRYPT_FORMAT_OBJECT_A,
        "FormatGenericAsnGuid"
    },

    /*
     * Microsoft: Entra ID
     * 1.2.840.113556.1.5.284
     */
    {
        /*
         * [MS-DVRE]: Device Registration Enrollment Protocol
         * Section 3.1.4.2.1: New Request Processing
         *
         * [MS-DVRJ]: Device Registration Join Protocol
         * Section 3.1.5.1.1.3: Processing Details
         */
        "1.2.840.113556.1.5.284.1",
        L"Entra ID: NTDS-DSA Invocation ID",
        L"Microsoft: Entra ID - NTDS-DSA Invocation ID",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        CRYPT_FORMAT_OBJECT_A,
        "FormatGenericAsnGuid"
    },
    {
        // Refer to OID: 1.2.840.113556.1.5.284.1
        "1.2.840.113556.1.5.284.2",
        L"Entra ID: Device ID",
        L"Microsoft: Entra ID - Device ID",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        CRYPT_FORMAT_OBJECT_A,
        "FormatGenericAsnGuid"
    },
    {
        // Refer to OID: 1.2.840.113556.1.5.284.1
        "1.2.840.113556.1.5.284.3",
        L"Entra ID: User ID",
        L"Microsoft: Entra ID - User ID",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        CRYPT_FORMAT_OBJECT_A,
        "FormatGenericAsnGuid"
    },
    {
        // Refer to OID: 1.2.840.113556.1.5.284.1
        "1.2.840.113556.1.5.284.4",
        L"Entra ID: Domain ID",
        L"Microsoft: Entra ID - Domain ID",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        CRYPT_FORMAT_OBJECT_A,
        "FormatGenericAsnGuid"
    },
    {
        "1.2.840.113556.1.5.284.5",
        L"Entra ID: Tenant ID",
        L"Microsoft: Entra ID - Tenant ID",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        CRYPT_FORMAT_OBJECT_A,
        "FormatGenericAsnGuid"
    },
    {
        "1.2.840.113556.1.5.284.7",
        L"Entra ID: Join Type",
        L"Microsoft: Entra ID - Join Type",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        CRYPT_FORMAT_OBJECT_A,
        "FormatEntraIdJoinType"
    },
    {
        "1.2.840.113556.1.5.284.8",
        L"Entra ID: Tenant Region",
        L"Microsoft: Entra ID - Tenant Region",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        CRYPT_FORMAT_OBJECT_A,
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
        CRYPT_FORMAT_OBJECT_A,
        "FormatIntuneDeviceId"
    },
    {
        "1.2.840.113556.5.6",
        L"Intune: Account ID",
        L"Microsoft: Intune - Account ID",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        CRYPT_FORMAT_OBJECT_A,
        "FormatGenericAsnGuid"
    },
    {
        "1.2.840.113556.5.10",
        L"Intune: User ID",
        L"Microsoft: Intune - User ID",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        CRYPT_FORMAT_OBJECT_A,
        "FormatGenericAsnGuid"
    },
#ifdef _DEBUG
    {
        "1.2.840.113556.5.11",
        L"Intune: Unknown (11)",
        L"Microsoft: Intune - Unknown (11)",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        CRYPT_FORMAT_OBJECT_A,
        "FormatGenericAsnGuid"
    },
#endif
    {
        "1.2.840.113556.5.14",
        L"Intune: Entra ID Tenant ID",
        L"Microsoft: Intune - Entra ID Tenant ID",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        CRYPT_FORMAT_OBJECT_A,
        "FormatGenericAsnGuid"
    },
#ifdef _DEBUG
    {
        "1.2.840.113556.5.15",
        L"Intune: Unknown (15)",
        L"Microsoft: Intune - Unknown (15)",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        CRYPT_FORMAT_OBJECT_A,
        "FormatGenericAsnInteger"
    },
    {
        "1.2.840.113556.5.16",
        L"Intune: Unknown (16)",
        L"Microsoft: Intune - Unknown (16)",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        CRYPT_FORMAT_OBJECT_A,
        "FormatGenericAsnInteger"
    },
    {
        "1.2.840.113556.5.17",
        L"Intune: Unknown (17)",
        L"Microsoft: Intune - Unknown (17)",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        CRYPT_FORMAT_OBJECT_A,
        "FormatGenericAsnInteger"
    },
    {
        "1.2.840.113556.5.18",
        L"Intune: Unknown (18)",
        L"Microsoft: Intune - Unknown (18)",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        CRYPT_FORMAT_OBJECT_A,
        "FormatGenericAsnInteger"
    },
    {
        "1.2.840.113556.5.19",
        L"Intune: Unknown (19)",
        L"Microsoft: Intune - Unknown (19)",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        CRYPT_FORMAT_OBJECT_A,
        "FormatGenericAsnInteger"
    },
    {
        "1.2.840.113556.5.23",
        L"Intune: Unknown (23)",
        L"Microsoft: Intune - Unknown (23)",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "1.2.840.113556.5.24",
        L"Intune: Unknown (24)",
        L"Microsoft: Intune - Unknown (24)",
        CRYPT_EXT_OR_ATTR_OID_GROUP_ID,
        NULL,
        NULL
    },
#endif

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
     * Netscape
     * 2.16.840.1.113730
     */
    {
        "2.16.840.1.113730.4.1",
        L"Netscape Server Gated Cryptography (SGC)",
        L"Netscape: Server Gated Cryptography (SGC)",
        CRYPT_ENHKEY_USAGE_OID_GROUP_ID,
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
        L"Sectigo S/MIME Certificate (Class 1)",
        L"Sectigo: S/MIME Certificate (Class 1) Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // Secure Server
        "1.3.6.1.4.1.6449.1.2.1.3.1",
        L"Sectigo TLS Certificate",
        L"Sectigo: TLS Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // Software Publisher
        "1.3.6.1.4.1.6449.1.2.1.3.2",
        L"Sectigo Code Signing Certificate",
        L"Sectigo: Code Signing Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // InstantSSL
        "1.3.6.1.4.1.6449.1.2.1.3.4",
        L"Sectigo Organization Validated (OV) TLS Certificate",
        L"Sectigo: Organization Validated (OV) TLS Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // Corporate Secure Email
        "1.3.6.1.4.1.6449.1.2.1.3.5",
        L"Sectigo S/MIME Certificate (Class 2)",
        L"Sectigo: S/MIME Certificate (Class 2) Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // Enterprise-Wide Secure Email
        "1.3.6.1.4.1.6449.1.2.1.3.6",
        L"Sectigo S/MIME Certificate (Class 3)",
        L"Sectigo: S/MIME Certificate (Class 3) Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "1.3.6.1.4.1.6449.1.2.1.3.8",
        L"Sectigo Timestamping Certificate",
        L"Sectigo: Timestamping Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "1.3.6.1.4.1.6449.1.2.1.5.1",
        L"Sectigo Extended Validation (EV) TLS Certificate",
        L"Sectigo: Extended Validation (EV) TLS Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "1.3.6.1.4.1.6449.1.2.1.6.1",
        L"Sectigo Extended Validation (EV) Code Signing Certificate",
        L"Sectigo: Extended Validation (EV) Code Signing Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "1.3.6.1.4.1.6449.1.2.1.6.6",
        L"Sectigo Document Signing (local)",
        L"Sectigo: Document Signing (local) Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "1.3.6.1.4.1.6449.1.2.1.6.7",
        L"Sectigo Document Signing (remote)",
        L"Sectigo: Document Signing (remote) Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        "1.3.6.1.4.1.6449.1.2.1.6.8",
        L"Sectigo Document Signing (external trusted partner)",
        L"Sectigo: Document Signing (external trusted partner) Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },
    {
        // DV Secure Server
        "1.3.6.1.4.1.6449.1.2.2.7",
        L"Sectigo Domain Validated (DV) TLS Certificate",
        L"Sectigo: Domain Validated (DV) TLS Certificate Policy",
        CRYPT_POLICY_OID_GROUP_ID,
        NULL,
        NULL
    },

    /*
     * VeriSign
     * 2.16.840.1.113733
     */
    {
        "2.16.840.1.113733.1.8.1",
        L"VeriSign Server Gated Cryptography (SGC)",
        L"VeriSign: Server Gated Cryptography (SGC)",
        CRYPT_ENHKEY_USAGE_OID_GROUP_ID,
        NULL,
        NULL
    }
};

// Number of registration information elements
DWORD g_cRegInfo = sizeof(g_rgRegInfo) / sizeof(CERTUIEXTS_REG_INFO);
