#pragma once

/*
 * Tag classes
 *
 * Bits 7 & 8 in tag byte
 */

#define ASN_UNIVERSAL       0x00
#define ASN_APPLICATION     0x40
#define ASN_CONTEXT         0x80
#define ASN_PRIVATE         0xC0


/*
 * Tag value encodings
 *
 * Bit 6 in tag byte
 */

#define ASN_PRIMITIVE       0x00
#define ASN_CONSTRUCTED     0x20


/*
 * Tags
 *
 * Bits 1 - 5 in tag byte
 */

#define ASN_BOOLEAN             0x01                            // BOOLEAN
#define ASN_INTEGER             0x02                            // INTEGER
#define ASN_BIT_STRING          0x03                            // BIT STRING
#define ASN_OCTET_STRING        0x04                            // OCTET STRING
#define ASN_NULL                0x05                            // NULL
#define ASN_OBJECT_IDENTIFIER   0x06                            // OBJECT IDENTIFIER
#define ASN_OBJECT_DESCRIPTOR   0x07                            // ObjectDescriptor
#define ASN_EXTERNAL            0x08                            // EXTERNAL
#define ASN_INSTANCE_OF         0x08                            // INSTANCE OF
#define ASN_REAL                0x09                            // REAL
#define ASN_ENUMERATED          0x0A                            // ENUMERATED
#define ASN_EMBEDDED_PDV        0x0B                            // EMBEDDED PDV
#define ASN_UTF8_STRING         0x0C                            // UTF8String
#define ASN_RELATIVE_OID        0x0D                            // RELATIVE-OID
#define ASN_TIME                0x0E                            // TIME
#define ASN_SEQUENCE            (0x10 | ASN_CONSTRUCTED)        // SEQUENCE
#define ASN_SEQUENCE_OF         (0x10 | ASN_CONSTRUCTED)        // SEQUENCE OF
#define ASN_SET                 (0x11 | ASN_CONSTRUCTED)        // SET
#define ASN_SET_OF              (0x11 | ASN_CONSTRUCTED)        // SET OF
#define ASN_NUMERIC_STRING      0x12                            // NumericString
#define ASN_PRINTABLE_STRING    0x13                            // PrintableString
#define ASN_T61_STRING          0x14                            // T61String
#define ASN_TELETEX_STRING      0x14                            // TeletexString
#define ASN_VIDEOTEX_STRING     0x15                            // VideotexString
#define ASN_IA5_STRING          0x16                            // IA5String
#define ASN_UTC_TIME            0x17                            // UTCTime
#define ASN_GENERALIZED_TIME    0x18                            // GeneralizedTime
#define ASN_GRAPHIC_STRING      0x19                            // GraphicString
#define ASN_ISO646_STRING       0x1A                            // ISO646String
#define ASN_VISIBLE_STRING      0x1A                            // VisibleString
#define ASN_GENERAL_STRING      0x1B                            // GeneralString
#define ASN_UNIVERSAL_STRING    0x1C                            // UniversalString
#define ASN_CHARACTER_STRING    0x1D                            // CHARACTER STRING
#define ASN_BMP_STRING          0x1E                            // BMPString
#define ASN_DATE                0x1F                            // DATE
#define ASN_TIME_OF_DAY         0x20                            // TIME-OF-DAY
#define ASN_DATE_TIME           0x21                            // DATE-TIME
#define ASN_DURATION            0x22                            // DURATION

/*
 * Integers
 */

// Minimum bytes to encode a 64-bit signed integer
#define ASN_TYPE_INT64_MIN_CB 3

// Maximum bytes to encode a 64-bit signed integer
#define ASN_TYPE_INT64_MAX_CB 10

// Minimum length value for an integer
#define ASN_LENGTH_INT_MIN_CB 1

// Maximum length value for a 64-bit signed integer
#define ASN_LENGTH_INT64_MAX_CB 8


/*
 * Security Identifiers (SIDs)
 */

// The shortest valid SID is of the form S-X-Y-Z, where:
// - S is the literal character "S"
// - X is the revision level
// - Y is the identifier authority
// - Z is one or more subauthorities
//
// Encoded as an octet string this corresponds to 7 bytes.
#define ASN_SID_VALUE_MIN_CB 7
#define ASN_SID_TLV_MIN_CB (ASN_SID_VALUE_MIN_CB + 2)


/*
 * Miscellaneous constants
 */

// Lengths larger than 127 are encoded as multiple bytes. The initial length
// byte has bit 8 set to 1, with the remaining bits indicating the number of
// bytes which encode the length.
#define ASN_LENGTH_SINGLE_BYTE_MAX_CB 0x7F
