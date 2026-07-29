#include "connection_table.h"

#include <stdlib.h>
#include <string.h>

_Static_assert(
    CONNECTION_HASH_SIZE != 0u &&
        (CONNECTION_HASH_SIZE & (CONNECTION_HASH_SIZE - 1u)) == 0u,
    "CONNECTION_HASH_SIZE must be a power of two");

typedef struct CONNECTION_INFO {
    CONNECTION_KEY key;
    CONNECTION_ADDRESS destination_address;
    UINT16 destination_port;
    UINT32 proxy_config_id;
    BOOL is_tracked;
    CONNECTION_DECISION decision;
    volatile LONG64 last_activity;
    struct CONNECTION_INFO *next;
} CONNECTION_INFO;

struct CONNECTION_TABLE {
    CONNECTION_INFO *buckets[CONNECTION_HASH_SIZE];
    SRWLOCK lock;
    SIZE_T entry_count;
};

static BOOL connection_protocol_is_valid(UINT8 protocol)
{
    return protocol == (UINT8)IPPROTO_TCP ||
           protocol == (UINT8)IPPROTO_UDP;
}

static BOOL connection_family_is_valid(ADDRESS_FAMILY family)
{
    return family == AF_INET || family == AF_INET6;
}

static BOOL connection_decision_is_valid(CONNECTION_DECISION decision)
{
    return decision == CONNECTION_DECISION_NONE ||
           decision == CONNECTION_DECISION_DIRECT ||
           decision == CONNECTION_DECISION_PROXY ||
           decision == CONNECTION_DECISION_BLOCK;
}

static SIZE_T connection_address_size(ADDRESS_FAMILY family)
{
    if (family == AF_INET) {
        return CONNECTION_IPV4_ADDRESS_SIZE;
    }
    if (family == AF_INET6) {
        return CONNECTION_IPV6_ADDRESS_SIZE;
    }
    return 0u;
}

static const UINT8 *connection_address_bytes(
    const CONNECTION_ADDRESS *address,
    ADDRESS_FAMILY family)
{
    return family == AF_INET ? address->ipv4 : address->ipv6;
}

static UINT8 *connection_address_bytes_mutable(
    CONNECTION_ADDRESS *address,
    ADDRESS_FAMILY family)
{
    return family == AF_INET ? address->ipv4 : address->ipv6;
}

static BOOL connection_key_is_valid(const CONNECTION_KEY *key)
{
    return key != NULL &&
           connection_protocol_is_valid(key->protocol) &&
           connection_family_is_valid(key->family);
}

static void connection_address_copy(
    CONNECTION_ADDRESS *destination,
    const CONNECTION_ADDRESS *source,
    ADDRESS_FAMILY family)
{
    SIZE_T address_size = connection_address_size(family);

    memset(destination, 0, sizeof(*destination));
    memcpy(
        connection_address_bytes_mutable(destination, family),
        connection_address_bytes(source, family),
        address_size);
}

static void connection_key_copy(
    CONNECTION_KEY *destination,
    const CONNECTION_KEY *source)
{
    memset(destination, 0, sizeof(*destination));
    destination->protocol = source->protocol;
    destination->family = source->family;
    destination->source_port = source->source_port;
    connection_address_copy(
        &destination->source_address,
        &source->source_address,
        source->family);
}

static void connection_snapshot_copy(
    CONNECTION_SNAPSHOT *snapshot,
    const CONNECTION_INFO *entry)
{
    memset(snapshot, 0, sizeof(*snapshot));
    snapshot->family = entry->key.family;
    connection_address_copy(
        &snapshot->destination_address,
        &entry->destination_address,
        entry->key.family);
    snapshot->destination_port = entry->destination_port;
    snapshot->proxy_config_id = entry->proxy_config_id;
    snapshot->decision = entry->decision;
}

static BOOL connection_address_equal(
    const CONNECTION_ADDRESS *left,
    const CONNECTION_ADDRESS *right,
    ADDRESS_FAMILY family)
{
    SIZE_T address_size = connection_address_size(family);

    return memcmp(
               connection_address_bytes(left, family),
               connection_address_bytes(right, family),
               address_size) == 0;
}

static BOOL connection_key_equal(
    const CONNECTION_KEY *left,
    const CONNECTION_KEY *right)
{
    return left->protocol == right->protocol &&
           left->family == right->family &&
           left->source_port == right->source_port &&
           connection_address_equal(
               &left->source_address,
               &right->source_address,
               left->family);
}

static UINT32 fnv1a32_update(
    UINT32 hash,
    const UINT8 *bytes,
    SIZE_T byte_count)
{
    SIZE_T index;

    for (index = 0u; index < byte_count; ++index) {
        hash ^= bytes[index];
        hash *= 16777619u;
    }

    return hash;
}

static UINT32 connection_key_hash(const CONNECTION_KEY *key)
{
    UINT32 hash = 2166136261u;
    UINT8 family_tag = key->family == AF_INET ? 4u : 6u;
    UINT8 port_bytes[2];
    SIZE_T address_size = connection_address_size(key->family);

    port_bytes[0] = (UINT8)(key->source_port >> 8);
    port_bytes[1] = (UINT8)(key->source_port & 0xffu);

    hash = fnv1a32_update(hash, &key->protocol, 1u);
    hash = fnv1a32_update(hash, &family_tag, 1u);
    hash = fnv1a32_update(hash, port_bytes, 2u);
    hash = fnv1a32_update(
        hash,
        connection_address_bytes(&key->source_address, key->family),
        address_size);

    return hash;
}

static CONNECTION_INFO *connection_table_find_locked(
    CONNECTION_TABLE *table,
    const CONNECTION_KEY *key,
    UINT32 bucket_index)
{
    CONNECTION_INFO *entry = table->buckets[bucket_index];

    while (entry != NULL) {
        if (connection_key_equal(&entry->key, key)) {
            return entry;
        }
        entry = entry->next;
    }

    return NULL;
}

static ULONGLONG connection_entry_last_activity(
    const CONNECTION_INFO *entry)
{
    volatile LONG64 *activity =
        (volatile LONG64 *)&entry->last_activity;

    return (ULONGLONG)InterlockedCompareExchange64(activity, 0, 0);
}

static void connection_entry_initialize_last_activity(
    CONNECTION_INFO *entry,
    ULONGLONG last_activity)
{
    InterlockedExchange64(
        &entry->last_activity,
        (LONG64)last_activity);
}

static ULONGLONG connection_entry_update_last_activity_max(
    CONNECTION_INFO *entry,
    ULONGLONG desired_activity)
{
    LONG64 observed = InterlockedCompareExchange64(
        &entry->last_activity,
        0,
        0);

    for (;;) {
        ULONGLONG current_activity = (ULONGLONG)observed;
        LONG64 previous;

        if (desired_activity <= current_activity) {
            return current_activity;
        }

        previous = InterlockedCompareExchange64(
            &entry->last_activity,
            (LONG64)desired_activity,
            observed);
        if (previous == observed) {
            return desired_activity;
        }

        observed = previous;
    }
}

static void connection_info_list_free(CONNECTION_INFO *entries)
{
    while (entries != NULL) {
        CONNECTION_INFO *next = entries->next;
        free(entries);
        entries = next;
    }
}

CONNECTION_TABLE *connection_table_create(void)
{
    CONNECTION_TABLE *table =
        (CONNECTION_TABLE *)calloc(1u, sizeof(*table));

    if (table == NULL) {
        return NULL;
    }

    InitializeSRWLock(&table->lock);
    return table;
}

void connection_table_destroy(CONNECTION_TABLE *table)
{
    if (table == NULL) {
        return;
    }

    (void)connection_table_clear(table);
    free(table);
}

BOOL connection_address_set(
    CONNECTION_ADDRESS *address,
    ADDRESS_FAMILY family,
    const UINT8 *raw_address,
    SIZE_T raw_address_size)
{
    SIZE_T expected_size;

    if (address == NULL) {
        return FALSE;
    }

    memset(address, 0, sizeof(*address));
    expected_size = connection_address_size(family);

    if (expected_size == 0u ||
        raw_address == NULL ||
        raw_address_size != expected_size) {
        return FALSE;
    }

    memcpy(
        connection_address_bytes_mutable(address, family),
        raw_address,
        expected_size);
    return TRUE;
}

BOOL connection_key_set(
    CONNECTION_KEY *key,
    int protocol,
    ADDRESS_FAMILY family,
    const UINT8 *raw_source_address,
    SIZE_T raw_source_address_size,
    UINT16 source_port)
{
    if (key == NULL) {
        return FALSE;
    }

    memset(key, 0, sizeof(*key));

    if ((protocol != IPPROTO_TCP && protocol != IPPROTO_UDP) ||
        !connection_family_is_valid(family) ||
        !connection_address_set(
            &key->source_address,
            family,
            raw_source_address,
            raw_source_address_size)) {
        memset(key, 0, sizeof(*key));
        return FALSE;
    }

    key->protocol = (UINT8)protocol;
    key->family = family;
    key->source_port = source_port;
    return TRUE;
}

BOOL connection_key_bucket_index(
    const CONNECTION_KEY *key,
    UINT32 *bucket_index)
{
    if (bucket_index == NULL) {
        return FALSE;
    }

    *bucket_index = 0u;
    if (!connection_key_is_valid(key)) {
        return FALSE;
    }

    *bucket_index =
        connection_key_hash(key) & (CONNECTION_HASH_SIZE - 1u);
    return TRUE;
}

static BOOL connection_table_upsert_internal(
    CONNECTION_TABLE *table,
    const CONNECTION_KEY *key,
    const CONNECTION_ADDRESS *destination_address,
    UINT16 destination_port,
    UINT32 proxy_config_id,
    BOOL is_tracked,
    CONNECTION_DECISION decision,
    ULONGLONG last_activity)
{
    UINT32 bucket_index;
    CONNECTION_INFO *entry;
    BOOL is_new_entry = FALSE;

    if (table == NULL ||
        destination_address == NULL ||
        !connection_decision_is_valid(decision) ||
        !connection_key_bucket_index(key, &bucket_index)) {
        return FALSE;
    }

    AcquireSRWLockExclusive(&table->lock);
    entry = connection_table_find_locked(table, key, bucket_index);

    if (entry == NULL) {
        entry = (CONNECTION_INFO *)calloc(1u, sizeof(*entry));
        if (entry == NULL) {
            ReleaseSRWLockExclusive(&table->lock);
            return FALSE;
        }

        connection_key_copy(&entry->key, key);
        is_new_entry = TRUE;
    }

    connection_address_copy(
        &entry->destination_address,
        destination_address,
        key->family);
    entry->destination_port = destination_port;
    entry->proxy_config_id = proxy_config_id;
    entry->is_tracked = is_tracked ? TRUE : FALSE;
    entry->decision = decision;

    if (is_new_entry) {
        connection_entry_initialize_last_activity(entry, last_activity);
        entry->next = table->buckets[bucket_index];
        table->buckets[bucket_index] = entry;
        ++table->entry_count;
    } else {
        (void)connection_entry_update_last_activity_max(
            entry,
            last_activity);
    }

    ReleaseSRWLockExclusive(&table->lock);
    return TRUE;
}

BOOL connection_table_upsert(
    CONNECTION_TABLE *table,
    const CONNECTION_KEY *key,
    const CONNECTION_ADDRESS *destination_address,
    UINT16 destination_port,
    UINT32 proxy_config_id,
    BOOL is_tracked,
    ULONGLONG last_activity)
{
    return connection_table_upsert_internal(
        table,
        key,
        destination_address,
        destination_port,
        proxy_config_id,
        is_tracked,
        CONNECTION_DECISION_NONE,
        last_activity);
}

BOOL connection_table_upsert_decision(
    CONNECTION_TABLE *table,
    const CONNECTION_KEY *key,
    const CONNECTION_ADDRESS *destination_address,
    UINT16 destination_port,
    UINT32 proxy_config_id,
    BOOL is_tracked,
    CONNECTION_DECISION decision,
    ULONGLONG last_activity)
{
    return connection_table_upsert_internal(
        table,
        key,
        destination_address,
        destination_port,
        proxy_config_id,
        is_tracked,
        decision,
        last_activity);
}

BOOL connection_table_is_tracked(
    CONNECTION_TABLE *table,
    const CONNECTION_KEY *key)
{
    UINT32 bucket_index;
    CONNECTION_INFO *entry;
    BOOL is_tracked = FALSE;

    if (table == NULL ||
        !connection_key_bucket_index(key, &bucket_index)) {
        return FALSE;
    }

    AcquireSRWLockShared(&table->lock);
    entry = connection_table_find_locked(table, key, bucket_index);
    if (entry != NULL && entry->is_tracked) {
        is_tracked = TRUE;
    }
    ReleaseSRWLockShared(&table->lock);

    return is_tracked;
}

BOOL connection_table_touch_tracked(
    CONNECTION_TABLE *table,
    const CONNECTION_KEY *key,
    ULONGLONG now)
{
    UINT32 bucket_index;
    CONNECTION_INFO *entry;

    if (table == NULL ||
        !connection_key_bucket_index(key, &bucket_index)) {
        return FALSE;
    }

    AcquireSRWLockShared(&table->lock);
    entry = connection_table_find_locked(table, key, bucket_index);

    if (entry == NULL || !entry->is_tracked) {
        ReleaseSRWLockShared(&table->lock);
        return FALSE;
    }

    (void)connection_entry_update_last_activity_max(entry, now);
    ReleaseSRWLockShared(&table->lock);
    return TRUE;
}

BOOL connection_table_touch_decision(
    CONNECTION_TABLE *table,
    const CONNECTION_KEY *key,
    const CONNECTION_ADDRESS *expected_destination_address,
    UINT16 expected_destination_port,
    ULONGLONG activity,
    CONNECTION_SNAPSHOT *snapshot)
{
    UINT32 bucket_index;
    CONNECTION_INFO *entry;

    if (snapshot == NULL) {
        return FALSE;
    }

    memset(snapshot, 0, sizeof(*snapshot));
    if (table == NULL ||
        expected_destination_address == NULL ||
        !connection_key_bucket_index(key, &bucket_index)) {
        return FALSE;
    }

    AcquireSRWLockShared(&table->lock);
    entry = connection_table_find_locked(table, key, bucket_index);

    if (entry == NULL ||
        entry->decision == CONNECTION_DECISION_NONE ||
        entry->destination_port != expected_destination_port ||
        !connection_address_equal(
            &entry->destination_address,
            expected_destination_address,
            key->family)) {
        ReleaseSRWLockShared(&table->lock);
        return FALSE;
    }

    connection_snapshot_copy(snapshot, entry);
    (void)connection_entry_update_last_activity_max(entry, activity);
    ReleaseSRWLockShared(&table->lock);
    return TRUE;
}

BOOL connection_table_clear_decision_if_match(
    CONNECTION_TABLE *table,
    const CONNECTION_KEY *key,
    const CONNECTION_ADDRESS *expected_destination_address,
    UINT16 expected_destination_port,
    CONNECTION_DECISION expected_decision,
    ULONGLONG activity)
{
    UINT32 bucket_index;
    CONNECTION_INFO *entry;
    BOOL cleared = FALSE;

    if (table == NULL ||
        expected_destination_address == NULL ||
        expected_decision == CONNECTION_DECISION_NONE ||
        !connection_decision_is_valid(expected_decision) ||
        !connection_key_bucket_index(key, &bucket_index)) {
        return FALSE;
    }

    AcquireSRWLockExclusive(&table->lock);
    entry = connection_table_find_locked(table, key, bucket_index);

    if (entry != NULL &&
        entry->decision == expected_decision &&
        entry->destination_port == expected_destination_port &&
        connection_address_equal(
            &entry->destination_address,
            expected_destination_address,
            key->family)) {
        entry->decision = CONNECTION_DECISION_NONE;
        (void)connection_entry_update_last_activity_max(entry, activity);
        cleared = TRUE;
    }

    ReleaseSRWLockExclusive(&table->lock);
    return cleared;
}

BOOL connection_table_get_full(
    CONNECTION_TABLE *table,
    const CONNECTION_KEY *key,
    ULONGLONG now,
    CONNECTION_SNAPSHOT *snapshot)
{
    UINT32 bucket_index;
    CONNECTION_INFO *entry;

    if (snapshot == NULL) {
        return FALSE;
    }

    memset(snapshot, 0, sizeof(*snapshot));
    if (table == NULL ||
        !connection_key_bucket_index(key, &bucket_index)) {
        return FALSE;
    }

    AcquireSRWLockShared(&table->lock);
    entry = connection_table_find_locked(table, key, bucket_index);

    if (entry == NULL) {
        ReleaseSRWLockShared(&table->lock);
        return FALSE;
    }

    connection_snapshot_copy(snapshot, entry);
    (void)connection_entry_update_last_activity_max(entry, now);

    ReleaseSRWLockShared(&table->lock);
    return TRUE;
}

BOOL connection_table_remove(
    CONNECTION_TABLE *table,
    const CONNECTION_KEY *key)
{
    UINT32 bucket_index;
    CONNECTION_INFO **entry_link;
    CONNECTION_INFO *removed = NULL;
    BOOL was_removed;

    if (table == NULL ||
        !connection_key_bucket_index(key, &bucket_index)) {
        return FALSE;
    }

    AcquireSRWLockExclusive(&table->lock);
    entry_link = &table->buckets[bucket_index];

    while (*entry_link != NULL) {
        if (connection_key_equal(&(*entry_link)->key, key)) {
            removed = *entry_link;
            *entry_link = removed->next;
            removed->next = NULL;
            --table->entry_count;
            break;
        }
        entry_link = &(*entry_link)->next;
    }

    ReleaseSRWLockExclusive(&table->lock);
    was_removed = removed != NULL;
    free(removed);
    return was_removed;
}

SIZE_T connection_table_cleanup(
    CONNECTION_TABLE *table,
    ULONGLONG now,
    ULONGLONG ttl)
{
    UINT32 bucket_index;
    CONNECTION_INFO *garbage = NULL;
    SIZE_T removed_count = 0u;

    if (table == NULL) {
        return 0u;
    }

    AcquireSRWLockExclusive(&table->lock);

    for (bucket_index = 0u;
         bucket_index < CONNECTION_HASH_SIZE;
         ++bucket_index) {
        CONNECTION_INFO **entry_link =
            &table->buckets[bucket_index];

        while (*entry_link != NULL) {
            CONNECTION_INFO *entry = *entry_link;
            ULONGLONG age =
                now - connection_entry_last_activity(entry);

            if (age > ttl) {
                *entry_link = entry->next;
                entry->next = garbage;
                garbage = entry;
                --table->entry_count;
                ++removed_count;
            } else {
                entry_link = &entry->next;
            }
        }
    }

    ReleaseSRWLockExclusive(&table->lock);
    connection_info_list_free(garbage);
    return removed_count;
}

SIZE_T connection_table_clear(CONNECTION_TABLE *table)
{
    UINT32 bucket_index;
    CONNECTION_INFO *garbage = NULL;
    SIZE_T removed_count;

    if (table == NULL) {
        return 0u;
    }

    AcquireSRWLockExclusive(&table->lock);
    removed_count = table->entry_count;

    for (bucket_index = 0u;
         bucket_index < CONNECTION_HASH_SIZE;
         ++bucket_index) {
        CONNECTION_INFO *entry = table->buckets[bucket_index];

        while (entry != NULL) {
            CONNECTION_INFO *next = entry->next;
            entry->next = garbage;
            garbage = entry;
            entry = next;
        }

        table->buckets[bucket_index] = NULL;
    }

    table->entry_count = 0u;
    ReleaseSRWLockExclusive(&table->lock);

    connection_info_list_free(garbage);
    return removed_count;
}

SIZE_T connection_table_count(CONNECTION_TABLE *table)
{
    SIZE_T entry_count;

    if (table == NULL) {
        return 0u;
    }

    AcquireSRWLockShared(&table->lock);
    entry_count = table->entry_count;
    ReleaseSRWLockShared(&table->lock);
    return entry_count;
}

BOOL connection_table_find_udp_sender(
    CONNECTION_TABLE *table,
    ADDRESS_FAMILY family,
    UINT32 proxy_config_id,
    const CONNECTION_ADDRESS *remote_destination_address,
    UINT16 remote_destination_port,
    CONNECTION_KEY *client_key)
{
    UINT32 bucket_index;
    BOOL found = FALSE;
    ULONGLONG newest_activity = 0u;

    if (client_key == NULL) {
        return FALSE;
    }

    memset(client_key, 0, sizeof(*client_key));
    if (table == NULL ||
        remote_destination_address == NULL ||
        !connection_family_is_valid(family)) {
        return FALSE;
    }

    AcquireSRWLockShared(&table->lock);

    for (bucket_index = 0u;
         bucket_index < CONNECTION_HASH_SIZE;
         ++bucket_index) {
        CONNECTION_INFO *entry = table->buckets[bucket_index];

        while (entry != NULL) {
            if (entry->key.protocol == (UINT8)IPPROTO_UDP &&
                entry->key.family == family &&
                entry->proxy_config_id == proxy_config_id &&
                entry->destination_port == remote_destination_port &&
                connection_address_equal(
                    &entry->destination_address,
                    remote_destination_address,
                    family)) {
                ULONGLONG activity =
                    connection_entry_last_activity(entry);

                if (!found || activity > newest_activity) {
                    connection_key_copy(client_key, &entry->key);
                    newest_activity = activity;
                    found = TRUE;
                }
            }

            entry = entry->next;
        }
    }

    ReleaseSRWLockShared(&table->lock);
    return found;
}
