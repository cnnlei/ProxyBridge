#ifndef PROXYBRIDGE_CONNECTION_TABLE_H
#define PROXYBRIDGE_CONNECTION_TABLE_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CONNECTION_HASH_SIZE 4096u
#define CONNECTION_IPV4_ADDRESS_SIZE 4u
#define CONNECTION_IPV6_ADDRESS_SIZE 16u

typedef union CONNECTION_ADDRESS {
    UINT8 ipv4[CONNECTION_IPV4_ADDRESS_SIZE];
    UINT8 ipv6[CONNECTION_IPV6_ADDRESS_SIZE];
} CONNECTION_ADDRESS;

typedef enum CONNECTION_DECISION {
    CONNECTION_DECISION_NONE = 0,
    CONNECTION_DECISION_DIRECT = 1,
    CONNECTION_DECISION_PROXY = 2,
    CONNECTION_DECISION_BLOCK = 3
} CONNECTION_DECISION;

typedef struct CONNECTION_KEY {
    UINT8 protocol;
    ADDRESS_FAMILY family;
    UINT16 source_port;
    CONNECTION_ADDRESS source_address;
} CONNECTION_KEY;

typedef struct CONNECTION_SNAPSHOT {
    ADDRESS_FAMILY family;
    CONNECTION_ADDRESS destination_address;
    UINT16 destination_port;
    UINT32 proxy_config_id;
    CONNECTION_DECISION decision;
} CONNECTION_SNAPSHOT;

typedef struct CONNECTION_TABLE CONNECTION_TABLE;

/*
 * CONNECTION_TABLE is opaque and owns its SRWLOCK and nodes.
 * Callers must stop concurrent operations before connection_table_destroy().
 * connection_table_clear() keeps the table initialized and reusable.
 */
CONNECTION_TABLE *connection_table_create(void);
void connection_table_destroy(CONNECTION_TABLE *table);

BOOL connection_address_set(
    CONNECTION_ADDRESS *address,
    ADDRESS_FAMILY family,
    const UINT8 *raw_address,
    SIZE_T raw_address_size);

BOOL connection_key_set(
    CONNECTION_KEY *key,
    int protocol,
    ADDRESS_FAMILY family,
    const UINT8 *raw_source_address,
    SIZE_T raw_source_address_size,
    UINT16 source_port);

BOOL connection_key_bucket_index(
    const CONNECTION_KEY *key,
    UINT32 *bucket_index);

BOOL connection_table_upsert(
    CONNECTION_TABLE *table,
    const CONNECTION_KEY *key,
    const CONNECTION_ADDRESS *destination_address,
    UINT16 destination_port,
    UINT32 proxy_config_id,
    BOOL is_tracked,
    ULONGLONG last_activity);

BOOL connection_table_upsert_decision(
    CONNECTION_TABLE *table,
    const CONNECTION_KEY *key,
    const CONNECTION_ADDRESS *destination_address,
    UINT16 destination_port,
    UINT32 proxy_config_id,
    BOOL is_tracked,
    CONNECTION_DECISION decision,
    ULONGLONG last_activity);

BOOL connection_table_is_tracked(
    CONNECTION_TABLE *table,
    const CONNECTION_KEY *key);

/*
 * Performs one exact-key lookup and returns TRUE only for a tracked entry.
 * On TRUE, activity becomes max(previous, now). Misses, invalid keys, and
 * untracked entries return FALSE without mutation. No internal pointer or
 * snapshot is returned.
 */
BOOL connection_table_touch_tracked(
    CONNECTION_TABLE *table,
    const CONNECTION_KEY *key,
    ULONGLONG now);

BOOL connection_table_touch_decision(
    CONNECTION_TABLE *table,
    const CONNECTION_KEY *key,
    const CONNECTION_ADDRESS *expected_destination_address,
    UINT16 expected_destination_port,
    ULONGLONG activity,
    CONNECTION_SNAPSHOT *snapshot);

BOOL connection_table_clear_decision_if_match(
    CONNECTION_TABLE *table,
    const CONNECTION_KEY *key,
    const CONNECTION_ADDRESS *expected_destination_address,
    UINT16 expected_destination_port,
    CONNECTION_DECISION expected_decision,
    ULONGLONG activity);

BOOL connection_table_get_full(
    CONNECTION_TABLE *table,
    const CONNECTION_KEY *key,
    ULONGLONG now,
    CONNECTION_SNAPSHOT *snapshot);

BOOL connection_table_remove(
    CONNECTION_TABLE *table,
    const CONNECTION_KEY *key);

SIZE_T connection_table_cleanup(
    CONNECTION_TABLE *table,
    ULONGLONG now,
    ULONGLONG ttl);

SIZE_T connection_table_clear(CONNECTION_TABLE *table);
SIZE_T connection_table_count(CONNECTION_TABLE *table);

/*
 * This deliberately preserves the current UDP ambiguity: if several clients
 * share one remote endpoint, the entry with the greatest last_activity wins.
 * It is not a complete UDP session-demultiplexing design.
 */
BOOL connection_table_find_udp_sender(
    CONNECTION_TABLE *table,
    ADDRESS_FAMILY family,
    UINT32 proxy_config_id,
    const CONNECTION_ADDRESS *remote_destination_address,
    UINT16 remote_destination_port,
    CONNECTION_KEY *client_key);

#ifdef __cplusplus
}
#endif

#endif
