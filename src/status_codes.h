#ifndef __STATUS_CODES_H
#define __STATUS_CODES_H

/* Defined in status_codes.c */

typedef enum {
    OK                       = 200,
    Bad_Request              = 400,
    Not_Found                = 404,
    Server_Error             = 500,
    Request_Entity_Too_Large = 413,
    Method_Not_Allowed       = 405,
    Request_Timeout          = 408,
    Not_Implemented          = 501,
} http_status_code;

const char *stringify_statuscode(http_status_code status_code);

#endif /* __STATUS_CODES_H */
