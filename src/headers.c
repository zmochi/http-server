/* ANSI-C code produced by gperf version 3.1 */
/* Command-line: /opt/homebrew/bin/gperf -tI --output-file=headers.c
 * HTTP_fields.gperf  */
/* Computed positions: -k'1,3,14,22,$' */

#include "headers.h"

#if !(                                                                         \
    (' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) && ('%' == 37) && \
    ('&' == 38) && ('\'' == 39) && ('(' == 40) && (')' == 41) &&               \
    ('*' == 42) && ('+' == 43) && (',' == 44) && ('-' == 45) && ('.' == 46) && \
    ('/' == 47) && ('0' == 48) && ('1' == 49) && ('2' == 50) && ('3' == 51) && \
    ('4' == 52) && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) && \
    ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) && ('=' == 61) && \
    ('>' == 62) && ('?' == 63) && ('A' == 65) && ('B' == 66) && ('C' == 67) && \
    ('D' == 68) && ('E' == 69) && ('F' == 70) && ('G' == 71) && ('H' == 72) && \
    ('I' == 73) && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) && \
    ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) && ('R' == 82) && \
    ('S' == 83) && ('T' == 84) && ('U' == 85) && ('V' == 86) && ('W' == 87) && \
    ('X' == 88) && ('Y' == 89) && ('Z' == 90) && ('[' == 91) &&                \
    ('\\' == 92) && (']' == 93) && ('^' == 94) && ('_' == 95) &&               \
    ('a' == 97) && ('b' == 98) && ('c' == 99) && ('d' == 100) &&               \
    ('e' == 101) && ('f' == 102) && ('g' == 103) && ('h' == 104) &&            \
    ('i' == 105) && ('j' == 106) && ('k' == 107) && ('l' == 108) &&            \
    ('m' == 109) && ('n' == 110) && ('o' == 111) && ('p' == 112) &&            \
    ('q' == 113) && ('r' == 114) && ('s' == 115) && ('t' == 116) &&            \
    ('u' == 117) && ('v' == 118) && ('w' == 119) && ('x' == 120) &&            \
    ('y' == 121) && ('z' == 122) && ('{' == 123) && ('|' == 124) &&            \
    ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
#error                                                                         \
    "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gperf@gnu.org>."
#endif

#line 2 "HTTP_fields.gperf"

#include "../libs/picohttpparser.h"
#line 12 "HTTP_fields.gperf"
#include <string.h>

#define TOTAL_KEYWORDS  167
#define MIN_WORD_LENGTH 2
#define MAX_WORD_LENGTH 40
#define MIN_HASH_VALUE  5
#define MAX_HASH_VALUE  412
/* maximum key range = 408, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
    static unsigned int
    http_hash_header(register const char *str, register size_t len) {
    static unsigned short asso_values[] = {
        413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
        413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
        413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
        413, 413, 413, 30,  413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
        413, 413, 413, 413, 413, 413, 413, 413, 413, 0,   413, 15,  25,  75,
        35,  0,   55,  15,  413, 25,  135, 200, 65,  50,  45,  413, 155, 70,
        80,  55,  10,  50,  5,   413, 413, 413, 413, 413, 413, 413, 413, 85,
        155, 0,   60,  15,  5,   65,  60,  20,  413, 0,   0,   125, 0,   10,
        110, 413, 15,  0,   10,  95,  413, 0,   30,  0,   20,  413, 413, 413,
        413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
        413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
        413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
        413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
        413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
        413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
        413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
        413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
        413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
        413, 413, 413, 413};
    register unsigned int hval = len;

    switch ( hval ) {
        default:
            hval += asso_values[(unsigned char)str[21]];
        /*FALLTHROUGH*/
        case 21:
        case 20:
        case 19:
        case 18:
        case 17:
        case 16:
        case 15:
        case 14:
            hval += asso_values[(unsigned char)str[13]];
        /*FALLTHROUGH*/
        case 13:
        case 12:
        case 11:
        case 10:
        case 9:
        case 8:
        case 7:
        case 6:
        case 5:
        case 4:
        case 3:
            hval += asso_values[(unsigned char)str[2]];
        /*FALLTHROUGH*/
        case 2:
        case 1:
            hval += asso_values[(unsigned char)str[0]];
            break;
    }
    return hval + asso_values[(unsigned char)str[len - 1]];
}

static struct hash_header http_headerlist[] = {
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
#line 37 "HTTP_fields.gperf"
    {"Allow"},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
#line 26 "HTTP_fields.gperf"
    {"Accept-Ranges"},
    {"", NULL},
    {"", NULL},
#line 17 "HTTP_fields.gperf"
    {"Accept"},
#line 39 "HTTP_fields.gperf"
    {"Alt-Svc"},
    {"", NULL},
    {"", NULL},
#line 41 "HTTP_fields.gperf"
    {"Alternates"},
#line 25 "HTTP_fields.gperf"
    {"Accept-Post"},
#line 92 "HTTP_fields.gperf"
    {"If"},
#line 45 "HTTP_fields.gperf"
    {"Authorization"},
    {"", NULL},
#line 59 "HTTP_fields.gperf"
    {"Connection"},
#line 18 "HTTP_fields.gperf"
    {"Accept-Additions"},
#line 47 "HTTP_fields.gperf"
    {"Cache-Status"},
#line 46 "HTTP_fields.gperf"
    {"Cache-Control"},
#line 176 "HTTP_fields.gperf"
    {"Vary"},
#line 22 "HTTP_fields.gperf"
    {"Accept-Features"},
#line 49 "HTTP_fields.gperf"
    {"CalDAV-Timezones"},
#line 43 "HTTP_fields.gperf"
    {"Authentication-Control"},
#line 36 "HTTP_fields.gperf"
    {"Age"},
#line 61 "HTTP_fields.gperf"
    {"Content-Disposition"},
    {"", NULL},
#line 81 "HTTP_fields.gperf"
    {"Destination"},
#line 175 "HTTP_fields.gperf"
    {"Variant-Vary"},
    {"", NULL},
#line 44 "HTTP_fields.gperf"
    {"Authentication-Info"},
#line 34 "HTTP_fields.gperf"
    {"Access-Control-Request-Headers"},
    {"", NULL},
#line 69 "HTTP_fields.gperf"
    {"Content-Type"},
#line 66 "HTTP_fields.gperf"
    {"Content-Range"},
    {"", NULL},
#line 58 "HTTP_fields.gperf"
    {"Close"},
#line 70 "HTTP_fields.gperf"
    {"Cookie"},
#line 28 "HTTP_fields.gperf"
    {"Access-Control-Allow-Credentials"},
#line 78 "HTTP_fields.gperf"
    {"DAV"},
#line 60 "HTTP_fields.gperf"
    {"Content-Digest"},
#line 79 "HTTP_fields.gperf"
    {"Delta-Base"},
#line 65 "HTTP_fields.gperf"
    {"Content-Location"},
#line 33 "HTTP_fields.gperf"
    {"Access-Control-Max-Age"},
#line 127 "HTTP_fields.gperf"
    {"Position"},
#line 77 "HTTP_fields.gperf"
    {"Date"},
#line 182 "HTTP_fields.gperf"
    {"X-Frame-Options"},
#line 56 "HTTP_fields.gperf"
    {"Client-Cert"},
#line 181 "HTTP_fields.gperf"
    {"X-Content-Type-Options"},
#line 67 "HTTP_fields.gperf"
    {"Content-Security-Policy"},
#line 32 "HTTP_fields.gperf"
    {"Access-Control-Expose-Headers"},
#line 83 "HTTP_fields.gperf"
    {"DPoP-Nonce"},
    {"", NULL},
#line 126 "HTTP_fields.gperf"
    {"Ping-To"},
    {"", NULL},
#line 19 "HTTP_fields.gperf"
    {"Accept-CH"},
#line 101 "HTTP_fields.gperf"
    {"Keep-Alive"},
    {"", NULL},
#line 134 "HTTP_fields.gperf"
    {"Proxy-Status"},
#line 96 "HTTP_fields.gperf"
    {"If-Range"},
#line 91 "HTTP_fields.gperf"
    {"Host"},
#line 68 "HTTP_fields.gperf"
    {"Content-Security-Policy-Report-Only"},
    {"", NULL},
#line 24 "HTTP_fields.gperf"
    {"Accept-Patch"},
#line 130 "HTTP_fields.gperf"
    {"Priority"},
#line 53 "HTTP_fields.gperf"
    {"Cert-Not-After"},
#line 54 "HTTP_fields.gperf"
    {"Cert-Not-Before"},
#line 120 "HTTP_fields.gperf"
    {"Origin"},
#line 31 "HTTP_fields.gperf"
    {"Access-Control-Allow-Origin"},
#line 40 "HTTP_fields.gperf"
    {"Alt-Used"},
#line 48 "HTTP_fields.gperf"
    {"Cal-Managed-ID"},
#line 21 "HTTP_fields.gperf"
    {"Accept-Encoding"},
#line 128 "HTTP_fields.gperf"
    {"Prefer"},
    {"", NULL},
#line 29 "HTTP_fields.gperf"
    {"Access-Control-Allow-Headers"},
#line 82 "HTTP_fields.gperf"
    {"DPoP"},
    {"", NULL},
#line 162 "HTTP_fields.gperf"
    {"Sunset"},
    {"", NULL},
#line 100 "HTTP_fields.gperf"
    {"Include-Referred-Token-Binding-ID"},
#line 124 "HTTP_fields.gperf"
    {"Overwrite"},
#line 174 "HTTP_fields.gperf"
    {"User-Agent"},
#line 179 "HTTP_fields.gperf"
    {"Want-Repr-Digest"},
    {"", NULL},
    {"", NULL},
#line 133 "HTTP_fields.gperf"
    {"Proxy-Authorization"},
#line 23 "HTTP_fields.gperf"
    {"Accept-Language"},
#line 146 "HTTP_fields.gperf"
    {"Sec-Purpose"},
#line 94 "HTTP_fields.gperf"
    {"If-Modified-Since"},
    {"", NULL},
#line 35 "HTTP_fields.gperf"
    {"Access-Control-Request-Method"},
#line 118 "HTTP_fields.gperf"
    {"Optional-WWW-Authenticate"},
    {"", NULL},
    {"", NULL},
    {"", NULL},
#line 178 "HTTP_fields.gperf"
    {"Want-Content-Digest"},
#line 155 "HTTP_fields.gperf"
    {"Set-Cookie"},
#line 153 "HTTP_fields.gperf"
    {"Server"},
#line 51 "HTTP_fields.gperf"
    {"CDN-Cache-Control"},
#line 131 "HTTP_fields.gperf"
    {"Proxy-Authenticate"},
#line 98 "HTTP_fields.gperf"
    {"If-Unmodified-Since"},
    {"", NULL},
#line 73 "HTTP_fields.gperf"
    {"Cross-Origin-Opener-Policy"},
#line 57 "HTTP_fields.gperf"
    {"Client-Cert-Chain"},
#line 93 "HTTP_fields.gperf"
    {"If-Match"},
#line 38 "HTTP_fields.gperf"
    {"ALPN"},
    {"", NULL},
#line 62 "HTTP_fields.gperf"
    {"Content-Encoding"},
#line 150 "HTTP_fields.gperf"
    {"Sec-WebSocket-Key"},
#line 95 "HTTP_fields.gperf"
    {"If-None-Match"},
#line 88 "HTTP_fields.gperf"
    {"Forwarded"},
#line 121 "HTTP_fields.gperf"
    {"Origin-Agent-Cluster"},
#line 152 "HTTP_fields.gperf"
    {"Sec-WebSocket-Version"},
#line 151 "HTTP_fields.gperf"
    {"Sec-WebSocket-Protocol"},
#line 74 "HTTP_fields.gperf"
    {"Cross-Origin-Opener-Policy-Report-Only"},
    {"", NULL},
#line 132 "HTTP_fields.gperf"
    {"Proxy-Authentication-Info"},
#line 27 "HTTP_fields.gperf"
    {"Accept-Signature"},
#line 173 "HTTP_fields.gperf"
    {"Urgency"},
    {"", NULL},
#line 158 "HTTP_fields.gperf"
    {"SLUG"},
#line 148 "HTTP_fields.gperf"
    {"Sec-WebSocket-Accept"},
#line 63 "HTTP_fields.gperf"
    {"Content-Language"},
    {"", NULL},
    {"", NULL},
#line 149 "HTTP_fields.gperf"
    {"Sec-WebSocket-Extensions"},
#line 161 "HTTP_fields.gperf"
    {"Strict-Transport-Security"},
    {"", NULL},
    {"", NULL},
#line 119 "HTTP_fields.gperf"
    {"Ordering-Type"},
#line 105 "HTTP_fields.gperf"
    {"Link"},
#line 55 "HTTP_fields.gperf"
    {"Clear-Site-Data"},
#line 50 "HTTP_fields.gperf"
    {"Capsule-Protocol"},
#line 172 "HTTP_fields.gperf"
    {"Upgrade"},
#line 106 "HTTP_fields.gperf"
    {"Location"},
#line 144 "HTTP_fields.gperf"
    {"Schedule-Reply"},
#line 107 "HTTP_fields.gperf"
    {"Lock-Token"},
#line 122 "HTTP_fields.gperf"
    {"OSCORE"},
    {"", NULL},
#line 117 "HTTP_fields.gperf"
    {"OData-Version"},
#line 64 "HTTP_fields.gperf"
    {"Content-Length"},
    {"", NULL},
#line 42 "HTTP_fields.gperf"
    {"Apply-To-Redirect-Ref"},
    {"", NULL},
    {"", NULL},
#line 112 "HTTP_fields.gperf"
    {"Negotiate"},
#line 20 "HTTP_fields.gperf"
    {"Accept-Datetime"},
    {"", NULL},
#line 164 "HTTP_fields.gperf"
    {"TE"},
#line 71 "HTTP_fields.gperf"
    {"Cross-Origin-Embedder-Policy"},
#line 156 "HTTP_fields.gperf"
    {"Signature"},
#line 115 "HTTP_fields.gperf"
    {"OData-Isolation"},
    {"", NULL},
    {"", NULL},
#line 154 "HTTP_fields.gperf"
    {"Server-Timing"},
    {"", NULL},
#line 159 "HTTP_fields.gperf"
    {"SoapAction"},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
#line 72 "HTTP_fields.gperf"
    {"Cross-Origin-Embedder-Policy-Report-Only"},
#line 116 "HTTP_fields.gperf"
    {"OData-MaxVersion"},
    {"", NULL},
#line 103 "HTTP_fields.gperf"
    {"Last-Event-ID"},
#line 89 "HTTP_fields.gperf"
    {"From"},
#line 137 "HTTP_fields.gperf"
    {"Range"},
    {"", NULL},
    {"", NULL},
    {"", NULL},
#line 125 "HTTP_fields.gperf"
    {"Ping-From"},
#line 160 "HTTP_fields.gperf"
    {"Status-URI"},
    {"", NULL},
#line 139 "HTTP_fields.gperf"
    {"Referer"},
#line 177 "HTTP_fields.gperf"
    {"Via"},
    {"", NULL},
#line 84 "HTTP_fields.gperf"
    {"Early-Data"},
#line 167 "HTTP_fields.gperf"
    {"Traceparent"},
#line 169 "HTTP_fields.gperf"
    {"Trailer"},
    {"", NULL},
    {"", NULL},
#line 168 "HTTP_fields.gperf"
    {"Tracestate"},
#line 143 "HTTP_fields.gperf"
    {"Retry-After"},
#line 87 "HTTP_fields.gperf"
    {"Expires"},
    {"", NULL},
    {"", NULL},
#line 166 "HTTP_fields.gperf"
    {"Topic"},
    {"", NULL},
    {"", NULL},
#line 52 "HTTP_fields.gperf"
    {"CDN-Loop"},
    {"", NULL},
#line 80 "HTTP_fields.gperf"
    {"Depth"},
#line 86 "HTTP_fields.gperf"
    {"Expect"},
#line 123 "HTTP_fields.gperf"
    {"OSLC-Core-Version"},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
#line 145 "HTTP_fields.gperf"
    {"Schedule-Tag"},
#line 104 "HTTP_fields.gperf"
    {"Last-Modified"},
    {"", NULL},
    {"", NULL},
#line 97 "HTTP_fields.gperf"
    {"If-Schedule-Tag-Match"},
#line 147 "HTTP_fields.gperf"
    {"Sec-Token-Binding"},
#line 163 "HTTP_fields.gperf"
    {"TCN"},
    {"", NULL},
#line 135 "HTTP_fields.gperf"
    {"Public-Key-Pins"},
#line 180 "HTTP_fields.gperf"
    {"WWW-Authenticate"},
#line 99 "HTTP_fields.gperf"
    {"IM"},
    {"", NULL},
#line 16 "HTTP_fields.gperf"
    {"A-IM"},
    {"", NULL},
    {"", NULL},
#line 165 "HTTP_fields.gperf"
    {"Timeout"},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
#line 140 "HTTP_fields.gperf"
    {"Refresh"},
#line 30 "HTTP_fields.gperf"
    {"Access-Control-Allow-Methods"},
#line 85 "HTTP_fields.gperf"
    {"ETag"},
#line 110 "HTTP_fields.gperf"
    {"Meter"},
    {"", NULL},
#line 138 "HTTP_fields.gperf"
    {"Redirect-Ref"},
    {"", NULL},
#line 76 "HTTP_fields.gperf"
    {"DASL"},
    {"", NULL},
    {"", NULL},
#line 136 "HTTP_fields.gperf"
    {"Public-Key-Pins-Report-Only"},
#line 75 "HTTP_fields.gperf"
    {"Cross-Origin-Resource-Policy"},
    {"", NULL},
    {"", NULL},
    {"", NULL},
#line 108 "HTTP_fields.gperf"
    {"Max-Forwards"},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
#line 129 "HTTP_fields.gperf"
    {"Preference-Applied"},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
#line 157 "HTTP_fields.gperf"
    {"Signature-Input"},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
#line 114 "HTTP_fields.gperf"
    {"OData-EntityId"},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
#line 90 "HTTP_fields.gperf"
    {"Hobareg"},
    {"", NULL},
    {"", NULL},
    {"", NULL},
#line 142 "HTTP_fields.gperf"
    {"Repr-Digest"},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
#line 141 "HTTP_fields.gperf"
    {"Replay-Nonce"},
    {"", NULL},
    {"", NULL},
#line 102 "HTTP_fields.gperf"
    {"Label"},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
#line 170 "HTTP_fields.gperf"
    {"Transfer-Encoding"},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
#line 113 "HTTP_fields.gperf"
    {"NEL"},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
#line 171 "HTTP_fields.gperf"
    {"TTL"},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
#line 109 "HTTP_fields.gperf"
    {"Memento-Datetime"},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
    {"", NULL},
#line 111 "HTTP_fields.gperf"
    {"MIME-Version"}};

struct hash_header *http_get_header(register const char *str,
                                    register size_t      len) {
    if ( len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH ) {
        register unsigned int key = http_hash_header(str, len);

        if ( key <= MAX_HASH_VALUE ) {
            register const char *s = http_headerlist[key].name;

            if ( *str == *s && !strncmp(str + 1, s + 1, len - 1) &&
                 s[len] == '\0' )
                return &http_headerlist[key];
        }
    }
    return 0;
}
#line 183 "HTTP_fields.gperf"

int http_set_header(const char *name, size_t name_len,
                    struct phr_header *req_header) {
    if ( name_len <= MAX_WORD_LENGTH && name_len >= MIN_WORD_LENGTH ) {

        unsigned int key = http_hash_header(name, name_len);

        if ( key <= MAX_HASH_VALUE ) {

            http_headerlist[key].req_header = req_header;
            return 0; // success
        }
    }
    return 1; // Invalid header
}
