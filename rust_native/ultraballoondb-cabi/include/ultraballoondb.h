#ifndef ULTRABALLOONDB_H
#define ULTRABALLOONDB_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
  #if defined(UBDB_CABI_BUILD)
    #define UBDB_API __declspec(dllexport)
  #else
    #define UBDB_API __declspec(dllimport)
  #endif
  #define UBDB_CALL __cdecl
#else
  #define UBDB_API __attribute__((visibility("default")))
  #define UBDB_CALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define UBDB_ABI_VERSION_V1 1u
#define UBDB_STATUS_OK 0
#define UBDB_STATUS_INVALID_ARGUMENT 1
#define UBDB_STATUS_NULL_POINTER 2
#define UBDB_STATUS_BUFFER_TOO_SMALL 3
#define UBDB_STATUS_PROTOCOL 4
#define UBDB_STATUS_BACKEND 5
#define UBDB_STATUS_CLOSED 6
#define UBDB_STATUS_IO 7
#define UBDB_STATUS_PANIC 255

typedef struct ubdb_protocol_config_v1 {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t max_frame_bytes;
    uint32_t max_requests_per_connection;
    uint32_t max_read_payload_bytes;
    uint32_t max_write_payload_bytes;
    uint64_t io_timeout_millis;
    uint8_t loopback_only;
    uint8_t reserved[7];
} ubdb_protocol_config_v1;

typedef struct ubdb_backend_health_v1 {
    uint32_t struct_size;
    uint32_t abi_version;
    uint8_t healthy;
    uint8_t read_only;
    uint8_t reserved[6];
    uint64_t generation;
} ubdb_backend_health_v1;

typedef struct ubdb_bytes_view_v1 {
    const uint8_t *ptr;
    size_t len;
} ubdb_bytes_view_v1;

typedef int32_t (UBDB_CALL *ubdb_health_callback_v1)(
    void *context,
    ubdb_backend_health_v1 *out_health
);

typedef int32_t (UBDB_CALL *ubdb_execute_callback_v1)(
    void *context,
    const uint8_t *request_ptr,
    size_t request_len,
    ubdb_bytes_view_v1 *out_response
);

typedef struct ubdb_backend_callbacks_v1 {
    uint32_t struct_size;
    uint32_t abi_version;
    void *context;
    ubdb_health_callback_v1 health;
    ubdb_execute_callback_v1 execute_read;
    ubdb_execute_callback_v1 execute_write;
} ubdb_backend_callbacks_v1;

typedef struct ubdb_session_handle_v1 ubdb_session_handle_v1;

UBDB_API uint32_t UBDB_CALL ubdb_abi_version_v1(void);
UBDB_API uint16_t UBDB_CALL ubdb_protocol_version_v1(void);
UBDB_API int32_t UBDB_CALL ubdb_protocol_config_init_v1(ubdb_protocol_config_v1 *out_config);
UBDB_API int32_t UBDB_CALL ubdb_session_create_v1(
    const ubdb_protocol_config_v1 *config,
    const ubdb_backend_callbacks_v1 *backend,
    uint64_t server_nonce,
    ubdb_session_handle_v1 **out_handle
);
UBDB_API int32_t UBDB_CALL ubdb_session_max_frame_bytes_v1(
    ubdb_session_handle_v1 *handle,
    uint32_t *out_max_frame_bytes
);
UBDB_API int32_t UBDB_CALL ubdb_session_process_frame_v1(
    ubdb_session_handle_v1 *handle,
    const uint8_t *request_ptr,
    size_t request_len,
    uint8_t *response_ptr,
    size_t response_capacity,
    size_t *out_response_len
);
UBDB_API int32_t UBDB_CALL ubdb_session_destroy_v1(ubdb_session_handle_v1 *handle);

#ifdef __cplusplus
}
#endif
#endif
