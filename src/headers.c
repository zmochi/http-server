/* ANSI-C code produced by gperf version 3.1 */
/* Command-line: /opt/homebrew/bin/gperf -I --output-file=headers.c HTTP_fields.gperf  */
/* Computed positions: -k'1,3,14,22,$' */

#if !((' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) \
      && ('%' == 37) && ('&' == 38) && ('\'' == 39) && ('(' == 40) \
      && (')' == 41) && ('*' == 42) && ('+' == 43) && (',' == 44) \
      && ('-' == 45) && ('.' == 46) && ('/' == 47) && ('0' == 48) \
      && ('1' == 49) && ('2' == 50) && ('3' == 51) && ('4' == 52) \
      && ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) \
      && ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) \
      && ('=' == 61) && ('>' == 62) && ('?' == 63) && ('A' == 65) \
      && ('B' == 66) && ('C' == 67) && ('D' == 68) && ('E' == 69) \
      && ('F' == 70) && ('G' == 71) && ('H' == 72) && ('I' == 73) \
      && ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) \
      && ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) \
      && ('R' == 82) && ('S' == 83) && ('T' == 84) && ('U' == 85) \
      && ('V' == 86) && ('W' == 87) && ('X' == 88) && ('Y' == 89) \
      && ('Z' == 90) && ('[' == 91) && ('\\' == 92) && (']' == 93) \
      && ('^' == 94) && ('_' == 95) && ('a' == 97) && ('b' == 98) \
      && ('c' == 99) && ('d' == 100) && ('e' == 101) && ('f' == 102) \
      && ('g' == 103) && ('h' == 104) && ('i' == 105) && ('j' == 106) \
      && ('k' == 107) && ('l' == 108) && ('m' == 109) && ('n' == 110) \
      && ('o' == 111) && ('p' == 112) && ('q' == 113) && ('r' == 114) \
      && ('s' == 115) && ('t' == 116) && ('u' == 117) && ('v' == 118) \
      && ('w' == 119) && ('x' == 120) && ('y' == 121) && ('z' == 122) \
      && ('{' == 123) && ('|' == 124) && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
#error "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gperf@gnu.org>."
#endif

#line 2 "HTTP_fields.gperf"

#include <http/headers.h>
#include <stdlib.h>
#include <string.h>

#define TOTAL_KEYWORDS 167
#define MIN_WORD_LENGTH 2
#define MAX_WORD_LENGTH 40
#define MIN_HASH_VALUE 5
#define MAX_HASH_VALUE 412
/* maximum key range = 408, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
http_hash_header (register const char *str, register size_t len)
{
  static unsigned short asso_values[] =
    {
      413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
      413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
      413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
      413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
      413, 413, 413, 413, 413,  30, 413, 413, 413, 413,
      413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
      413, 413, 413, 413, 413,   0, 413,  15,  25,  75,
       35,   0,  55,  15, 413,  25, 135, 200,  65,  50,
       45, 413, 155,  70,  80,  55,  10,  50,   5, 413,
      413, 413, 413, 413, 413, 413, 413,  85, 155,   0,
       60,  15,   5,  65,  60,  20, 413,   0,   0, 125,
        0,  10, 110, 413,  15,   0,  10,  95, 413,   0,
       30,   0,  20, 413, 413, 413, 413, 413, 413, 413,
      413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
      413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
      413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
      413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
      413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
      413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
      413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
      413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
      413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
      413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
      413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
      413, 413, 413, 413, 413, 413, 413, 413, 413, 413,
      413, 413, 413, 413, 413, 413
    };
  register unsigned int hval = len;

  switch (hval)
    {
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

static const char * http_headerlist[] =
  {
    "", "", "", "", "",
    "Allow",
    "", "", "", "", "", "", "",
    "Accept-Ranges",
    "", "",
    "Accept",
    "Alt-Svc",
    "", "",
    "Alternates",
    "Accept-Post",
    "If",
    "Authorization",
    "",
    "Connection",
    "Accept-Additions",
    "Cache-Status",
    "Cache-Control",
    "Vary",
    "Accept-Features",
    "CalDAV-Timezones",
    "Authentication-Control",
    "Age",
    "Content-Disposition",
    "",
    "Destination",
    "Variant-Vary",
    "",
    "Authentication-Info",
    "Access-Control-Request-Headers",
    "",
    "Content-Type",
    "Content-Range",
    "",
    "Close",
    "Cookie",
    "Access-Control-Allow-Credentials",
    "DAV",
    "Content-Digest",
    "Delta-Base",
    "Content-Location",
    "Access-Control-Max-Age",
    "Position",
    "Date",
    "X-Frame-Options",
    "Client-Cert",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Access-Control-Expose-Headers",
    "DPoP-Nonce",
    "",
    "Ping-To",
    "",
    "Accept-CH",
    "Keep-Alive",
    "",
    "Proxy-Status",
    "If-Range",
    "Host",
    "Content-Security-Policy-Report-Only",
    "",
    "Accept-Patch",
    "Priority",
    "Cert-Not-After",
    "Cert-Not-Before",
    "Origin",
    "Access-Control-Allow-Origin",
    "Alt-Used",
    "Cal-Managed-ID",
    "Accept-Encoding",
    "Prefer",
    "",
    "Access-Control-Allow-Headers",
    "DPoP",
    "",
    "Sunset",
    "",
    "Include-Referred-Token-Binding-ID",
    "Overwrite",
    "User-Agent",
    "Want-Repr-Digest",
    "", "",
    "Proxy-Authorization",
    "Accept-Language",
    "Sec-Purpose",
    "If-Modified-Since",
    "",
    "Access-Control-Request-Method",
    "Optional-WWW-Authenticate",
    "", "", "",
    "Want-Content-Digest",
    "Set-Cookie",
    "Server",
    "CDN-Cache-Control",
    "Proxy-Authenticate",
    "If-Unmodified-Since",
    "",
    "Cross-Origin-Opener-Policy",
    "Client-Cert-Chain",
    "If-Match",
    "ALPN",
    "",
    "Content-Encoding",
    "Sec-WebSocket-Key",
    "If-None-Match",
    "Forwarded",
    "Origin-Agent-Cluster",
    "Sec-WebSocket-Version",
    "Sec-WebSocket-Protocol",
    "Cross-Origin-Opener-Policy-Report-Only",
    "",
    "Proxy-Authentication-Info",
    "Accept-Signature",
    "Urgency",
    "",
    "SLUG",
    "Sec-WebSocket-Accept",
    "Content-Language",
    "", "",
    "Sec-WebSocket-Extensions",
    "Strict-Transport-Security",
    "", "",
    "Ordering-Type",
    "Link",
    "Clear-Site-Data",
    "Capsule-Protocol",
    "Upgrade",
    "Location",
    "Schedule-Reply",
    "Lock-Token",
    "OSCORE",
    "",
    "OData-Version",
    "Content-Length",
    "",
    "Apply-To-Redirect-Ref",
    "", "",
    "Negotiate",
    "Accept-Datetime",
    "",
    "TE",
    "Cross-Origin-Embedder-Policy",
    "Signature",
    "OData-Isolation",
    "", "",
    "Server-Timing",
    "",
    "SoapAction",
    "", "", "", "",
    "Cross-Origin-Embedder-Policy-Report-Only",
    "OData-MaxVersion",
    "",
    "Last-Event-ID",
    "From",
    "Range",
    "", "", "",
    "Ping-From",
    "Status-URI",
    "",
    "Referer",
    "Via",
    "",
    "Early-Data",
    "Traceparent",
    "Trailer",
    "", "",
    "Tracestate",
    "Retry-After",
    "Expires",
    "", "",
    "Topic",
    "", "",
    "CDN-Loop",
    "",
    "Depth",
    "Expect",
    "OSLC-Core-Version",
    "", "", "", "",
    "Schedule-Tag",
    "Last-Modified",
    "", "",
    "If-Schedule-Tag-Match",
    "Sec-Token-Binding",
    "TCN",
    "",
    "Public-Key-Pins",
    "WWW-Authenticate",
    "IM",
    "",
    "A-IM",
    "", "",
    "Timeout",
    "", "", "", "",
    "Refresh",
    "Access-Control-Allow-Methods",
    "ETag",
    "Meter",
    "",
    "Redirect-Ref",
    "",
    "DASL",
    "", "",
    "Public-Key-Pins-Report-Only",
    "Cross-Origin-Resource-Policy",
    "", "", "",
    "Max-Forwards",
    "", "", "", "", "",
    "Preference-Applied",
    "", "", "", "", "", "",
    "Signature-Input",
    "", "", "", "", "", "", "", "", "",
    "", "", "", "",
    "OData-EntityId",
    "", "", "", "", "", "", "", "", "",
    "", "", "",
    "Hobareg",
    "", "", "",
    "Repr-Digest",
    "", "", "", "", "",
    "Replay-Nonce",
    "", "",
    "Label",
    "", "", "", "", "", "", "", "", "",
    "", "",
    "Transfer-Encoding",
    "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "",
    "", "", "",
    "NEL",
    "", "", "", "", "", "", "", "", "",
    "", "", "", "", "",
    "TTL",
    "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "",
    "", "", "", "",
    "Memento-Datetime",
    "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "",
    "MIME-Version"
  };

const char *
http_lookup_header (register const char *str, register size_t len)
{
  if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      register unsigned int key = http_hash_header (str, len);

      if (key <= MAX_HASH_VALUE)
        {
          register const char *s = http_headerlist[key];

          if (*str == *s && !strncmp (str + 1, s + 1, len - 1) && s[len] == '\0')
            return s;
        }
    }
  return 0;
}
#line 181 "HTTP_fields.gperf"


struct header_hashset {
    /* a buffer containing all header values, pointed to by elements in @arr */
    char value_storage[REQ_HEADER_VALUES_MAX_SIZE];
    /* an array containing pointers to the value of each header. the value is
     * stored in @value_storage */
    struct header_value *arr;
    /* pointer to where in value_storage values can be inserted */
    char *value_storage_ptr;
};

const size_t arr_len  = MAX_HASH_VALUE;
const size_t arr_size = arr_len * sizeof(struct header_value);

extern inline struct header_hashset *malloc_init_hashset(void) {
    /* just an array of struct http_header*, the index for a header string @str
     * is given by http_hash_header(str, strlen(str)) */
    struct header_hashset *set = malloc(sizeof(struct header_hashset));
    set->arr                   = malloc(arr_size);
    memset(set->arr, 0, arr_size);
    /* TODO: can initialize in O(1) */
    set->value_storage_ptr = set->value_storage;
    /* TODO: check malloc() fail */

    return set;
}

extern inline void reset_header_hashset(struct header_hashset *set) {
    memset(set->arr, 0, arr_size);
    set->value_storage_ptr = set->value_storage;
}

extern inline void free_header_hashset(struct header_hashset *set) {
    free(set->arr);
    free(set);
}

struct header_value *http_get_header(struct header_hashset *set,
                                     const char *name, int name_len) {
    if ( name_len <= MAX_WORD_LENGTH && name_len >= MIN_WORD_LENGTH ) {

        unsigned int key = http_hash_header(name, name_len);

        if ( key <= MAX_HASH_VALUE && set->arr[key].value != NULL &&
             set->arr[key].value_len != 0 ) {
            return &set->arr[key];
        }
    }
    return NULL; // invalid header
}

int http_set_header(struct header_hashset *set, const char *name, int name_len,
                    const char *value, int value_len) {
    if ( name_len <= MAX_WORD_LENGTH && name_len >= MIN_WORD_LENGTH ) {

        unsigned int key = http_hash_header(name, name_len);

        if ( key <= MAX_HASH_VALUE ) {
            memcpy(set->value_storage_ptr, value, value_len);

            set->arr[key].value     = set->value_storage_ptr;
            set->arr[key].value_len = value_len;

            set->value_storage_ptr += value_len;

            return true; // success
        }
    }
    return false; // invalid header name
}
