
#define CHECK_SNPRINTF(dest, dest_size, ...) \
    do { \
        int result = snprintf(dest, dest_size, __VA_ARGS__); \
        if (result < 0 || result >= dest_size) { \
            indigo_logger(LOG_LEVEL_ERROR, "snprintf failed or buffer overflow occurred at line %d - Return value: %d", __LINE__, result); \
             goto done; \
        } \
    } while(0)

