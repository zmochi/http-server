#define offsetof(type, member)                                                 \
    ((size_t)((char *)((char *)(&((type *)0)->member) - (char *)0)))

#define container_of(item_ptr, container_type, member)                         \
    ((container_type *)((char *)item_ptr - offsetof(container_type, member)))
