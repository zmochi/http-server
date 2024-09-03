/* for offsetof() macro */
#include <stddef.h>

#ifndef __CONTAINER_OF_H
#define __CONTAINER_OF_H

#define container_of(item_ptr, container_type, member)                         \
    ((container_type *)((char *)item_ptr - offsetof(container_type, member)))

#endif /* __CONTAINER_OF_H */
