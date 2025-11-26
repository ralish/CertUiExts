#pragma once

/*
 * SPC Publisher Information
 * 1.3.6.1.4.1.311.2.1.12
 */

// Requested buffer size for formatted output
#define SPC_PUBLISHER_INFO_BUFFER_CB ((DWORD)512 * sizeof(WCHAR))

// ASN.1 tag for "Program name" (aka. project description)
#define SPC_PUBLISHER_INFO_PROGNAME_TAG (BYTE)(ASN_CONTEXT | ASN_CONSTRUCTED)

// ASN.1 tag for "More information" field (aka. URL)
#define SPC_PUBLISHER_INFO_MOREINFO_TAG (BYTE)(SPC_PUBLISHER_INFO_PROGNAME_TAG + 1)
