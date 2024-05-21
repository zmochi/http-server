#ifndef __STATUS_CODES_H
#define __STATUS_CODES_H
/* Defined in status_codes.c */
extern const char                 *status_codes_arr[];
extern struct status_codes_storage status_codes;

struct status_codes_storage {
    int          size;
    int          smallest_code;
    const char **storage;
};
#endif /* __STATUS_CODES_H */
