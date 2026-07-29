#include "../src/connection_table.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ARRAY_COUNT(values) (sizeof(values) / sizeof((values)[0]))

static const UINT8 IPV4_A[4] = {10u, 0u, 0u, 1u};
static const UINT8 IPV4_B[4] = {10u, 0u, 0u, 2u};
static const UINT8 IPV4_C[4] = {203u, 0u, 113u, 7u};
static const UINT8 IPV4_D[4] = {198u, 51u, 100u, 9u};
static const UINT8 IPV6_A[16] = {
    0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 1u
};
static const UINT8 IPV6_B[16] = {
    0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 0u,
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 2u
};
static const UINT8 IPV6_C[16] = {
    0x20u, 0x01u, 0x0du, 0xb8u, 0u, 0u, 0u, 1u,
    0u, 0u, 0u, 0u, 0u, 0u, 0u, 7u
};

static BOOL test_failure(
    const char *test_name,
    int line,
    const char *expression,
    const char *reason)
{
    fprintf(
        stderr,
        "FAIL %s line=%d expression=%s reason=%s\n",
        test_name,
        line,
        expression,
        reason);
    return FALSE;
}

#define CHECK(condition, reason)                                      \
    do {                                                              \
        if (!(condition)) {                                           \
            return test_failure(__func__, __LINE__, #condition, reason); \
        }                                                             \
    } while (0)

static BOOL make_key(
    CONNECTION_KEY *key,
    int protocol,
    ADDRESS_FAMILY family,
    const UINT8 *address,
    UINT16 port)
{
    SIZE_T size =
        family == AF_INET ? CONNECTION_IPV4_ADDRESS_SIZE :
        CONNECTION_IPV6_ADDRESS_SIZE;

    return connection_key_set(
        key,
        protocol,
        family,
        address,
        size,
        port);
}

static BOOL make_address(
    CONNECTION_ADDRESS *address,
    ADDRESS_FAMILY family,
    const UINT8 *bytes)
{
    SIZE_T size =
        family == AF_INET ? CONNECTION_IPV4_ADDRESS_SIZE :
        CONNECTION_IPV6_ADDRESS_SIZE;

    return connection_address_set(address, family, bytes, size);
}

static BOOL key_equal(
    const CONNECTION_KEY *left,
    const CONNECTION_KEY *right)
{
    SIZE_T size =
        left->family == AF_INET ? CONNECTION_IPV4_ADDRESS_SIZE :
        CONNECTION_IPV6_ADDRESS_SIZE;
    const UINT8 *left_address =
        left->family == AF_INET ?
        left->source_address.ipv4 : left->source_address.ipv6;
    const UINT8 *right_address =
        right->family == AF_INET ?
        right->source_address.ipv4 : right->source_address.ipv6;

    return left->protocol == right->protocol &&
           left->family == right->family &&
           left->source_port == right->source_port &&
           memcmp(left_address, right_address, size) == 0;
}

static BOOL snapshot_equal(
    const CONNECTION_SNAPSHOT *snapshot,
    ADDRESS_FAMILY family,
    const UINT8 *destination,
    UINT16 destination_port,
    UINT32 proxy_config_id)
{
    SIZE_T size =
        family == AF_INET ? CONNECTION_IPV4_ADDRESS_SIZE :
        CONNECTION_IPV6_ADDRESS_SIZE;
    const UINT8 *snapshot_address =
        family == AF_INET ?
        snapshot->destination_address.ipv4 :
        snapshot->destination_address.ipv6;

    return snapshot->family == family &&
           snapshot->destination_port == destination_port &&
           snapshot->proxy_config_id == proxy_config_id &&
           memcmp(snapshot_address, destination, size) == 0;
}

static BOOL snapshot_equal_decision(
    const CONNECTION_SNAPSHOT *snapshot,
    ADDRESS_FAMILY family,
    const UINT8 *destination,
    UINT16 destination_port,
    UINT32 proxy_config_id,
    CONNECTION_DECISION decision)
{
    return snapshot_equal(
               snapshot,
               family,
               destination,
               destination_port,
               proxy_config_id) &&
           snapshot->decision == decision;
}

static BOOL find_ipv4_keys_in_one_bucket(
    CONNECTION_KEY *keys,
    SIZE_T key_count,
    int protocol)
{
    UINT16 ports[CONNECTION_HASH_SIZE][4];
    UINT8 counts[CONNECTION_HASH_SIZE];
    UINT32 port;

    if (keys == NULL || key_count == 0u || key_count > 4u) {
        return FALSE;
    }

    memset(ports, 0, sizeof(ports));
    memset(counts, 0, sizeof(counts));

    for (port = 1u; port <= 65535u; ++port) {
        CONNECTION_KEY candidate;
        UINT32 bucket;
        UINT8 count;

        if (!make_key(
                &candidate,
                protocol,
                AF_INET,
                IPV4_A,
                (UINT16)port) ||
            !connection_key_bucket_index(&candidate, &bucket)) {
            return FALSE;
        }

        count = counts[bucket];
        if ((SIZE_T)count < key_count) {
            ports[bucket][count] = (UINT16)port;
            ++counts[bucket];

            if ((SIZE_T)counts[bucket] == key_count) {
                SIZE_T index;

                for (index = 0u; index < key_count; ++index) {
                    if (!make_key(
                            &keys[index],
                            protocol,
                            AF_INET,
                            IPV4_A,
                            ports[bucket][index])) {
                        return FALSE;
                    }
                }
                return TRUE;
            }
        }
    }

    return FALSE;
}

static BOOL test_protocol_collision(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY tcp_key;
    CONNECTION_KEY udp_key;
    CONNECTION_ADDRESS tcp_destination;
    CONNECTION_ADDRESS udp_destination;
    CONNECTION_SNAPSHOT snapshot;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&tcp_key, IPPROTO_TCP, AF_INET, IPV4_A, 41000u), "TCP key");
    CHECK(make_key(&udp_key, IPPROTO_UDP, AF_INET, IPV4_A, 41000u), "UDP key");
    CHECK(make_address(&tcp_destination, AF_INET, IPV4_C), "TCP destination");
    CHECK(make_address(&udp_destination, AF_INET, IPV4_D), "UDP destination");
    CHECK(connection_table_upsert(
        table, &tcp_key, &tcp_destination, 443u, 11u, TRUE, 10u), "insert TCP");
    CHECK(connection_table_upsert(
        table, &udp_key, &udp_destination, 53u, 12u, TRUE, 20u), "insert UDP");
    CHECK(connection_table_count(table) == 2u, "protocol keys collapsed");
    CHECK(connection_table_get_full(table, &tcp_key, 30u, &snapshot), "lookup TCP");
    CHECK(snapshot_equal(&snapshot, AF_INET, IPV4_C, 443u, 11u), "TCP mismatch");
    CHECK(connection_table_get_full(table, &udp_key, 31u, &snapshot), "lookup UDP");
    CHECK(snapshot_equal(&snapshot, AF_INET, IPV4_D, 53u, 12u), "UDP mismatch");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_reverse_insertion_order(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY tcp_key;
    CONNECTION_KEY udp_key;
    CONNECTION_ADDRESS tcp_destination;
    CONNECTION_ADDRESS udp_destination;
    CONNECTION_SNAPSHOT snapshot;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&tcp_key, IPPROTO_TCP, AF_INET, IPV4_A, 41001u), "TCP key");
    CHECK(make_key(&udp_key, IPPROTO_UDP, AF_INET, IPV4_A, 41001u), "UDP key");
    CHECK(make_address(&tcp_destination, AF_INET, IPV4_C), "TCP destination");
    CHECK(make_address(&udp_destination, AF_INET, IPV4_D), "UDP destination");
    CHECK(connection_table_upsert(
        table, &udp_key, &udp_destination, 5353u, 21u, TRUE, 10u), "insert UDP");
    CHECK(connection_table_upsert(
        table, &tcp_key, &tcp_destination, 8443u, 22u, TRUE, 20u), "insert TCP");
    CHECK(connection_table_get_full(table, &udp_key, 30u, &snapshot), "lookup UDP");
    CHECK(snapshot_equal(&snapshot, AF_INET, IPV4_D, 5353u, 21u), "UDP overwritten");
    CHECK(connection_table_get_full(table, &tcp_key, 31u, &snapshot), "lookup TCP");
    CHECK(snapshot_equal(&snapshot, AF_INET, IPV4_C, 8443u, 22u), "TCP mismatch");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_different_ports_control(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY first;
    CONNECTION_KEY second;
    CONNECTION_ADDRESS destination;
    CONNECTION_SNAPSHOT snapshot;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&first, IPPROTO_TCP, AF_INET, IPV4_A, 42000u), "first key");
    CHECK(make_key(&second, IPPROTO_TCP, AF_INET, IPV4_A, 42001u), "second key");
    CHECK(make_address(&destination, AF_INET, IPV4_C), "destination");
    CHECK(connection_table_upsert(
        table, &first, &destination, 80u, 31u, TRUE, 1u), "first insert");
    CHECK(connection_table_upsert(
        table, &second, &destination, 81u, 32u, TRUE, 2u), "second insert");
    CHECK(connection_table_count(table) == 2u, "ports collapsed");
    CHECK(connection_table_get_full(table, &first, 3u, &snapshot), "first lookup");
    CHECK(snapshot.destination_port == 80u &&
          snapshot.proxy_config_id == 31u, "first value mismatch");
    CHECK(connection_table_get_full(table, &second, 4u, &snapshot), "second lookup");
    CHECK(snapshot.destination_port == 81u &&
          snapshot.proxy_config_id == 32u, "second value mismatch");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_ipv4_ipv6_separation(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY ipv4_key;
    CONNECTION_KEY ipv6_key;
    CONNECTION_ADDRESS ipv4_destination;
    CONNECTION_ADDRESS ipv6_destination;
    CONNECTION_SNAPSHOT snapshot;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&ipv4_key, IPPROTO_TCP, AF_INET, IPV4_A, 43000u), "IPv4 key");
    CHECK(make_key(&ipv6_key, IPPROTO_TCP, AF_INET6, IPV6_A, 43000u), "IPv6 key");
    CHECK(make_address(&ipv4_destination, AF_INET, IPV4_C), "IPv4 destination");
    CHECK(make_address(&ipv6_destination, AF_INET6, IPV6_C), "IPv6 destination");
    CHECK(connection_table_upsert(
        table, &ipv4_key, &ipv4_destination, 443u, 41u, TRUE, 1u), "IPv4 insert");
    CHECK(connection_table_upsert(
        table, &ipv6_key, &ipv6_destination, 443u, 42u, TRUE, 2u), "IPv6 insert");
    CHECK(connection_table_count(table) == 2u, "families collapsed");
    CHECK(connection_table_get_full(table, &ipv4_key, 3u, &snapshot), "IPv4 lookup");
    CHECK(snapshot_equal(&snapshot, AF_INET, IPV4_C, 443u, 41u), "IPv4 mismatch");
    CHECK(connection_table_get_full(table, &ipv6_key, 4u, &snapshot), "IPv6 lookup");
    CHECK(snapshot_equal(&snapshot, AF_INET6, IPV6_C, 443u, 42u), "IPv6 mismatch");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_different_local_ipv4(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY first;
    CONNECTION_KEY second;
    CONNECTION_ADDRESS destination;
    CONNECTION_SNAPSHOT snapshot;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&first, IPPROTO_UDP, AF_INET, IPV4_A, 44000u), "first key");
    CHECK(make_key(&second, IPPROTO_UDP, AF_INET, IPV4_B, 44000u), "second key");
    CHECK(make_address(&destination, AF_INET, IPV4_C), "destination");
    CHECK(connection_table_upsert(
        table, &first, &destination, 53u, 51u, TRUE, 1u), "first insert");
    CHECK(connection_table_upsert(
        table, &second, &destination, 53u, 52u, TRUE, 2u), "second insert");
    CHECK(connection_table_count(table) == 2u, "IPv4 addresses collapsed");
    CHECK(connection_table_get_full(table, &first, 3u, &snapshot), "first lookup");
    CHECK(snapshot.proxy_config_id == 51u, "first config mismatch");
    CHECK(connection_table_get_full(table, &second, 4u, &snapshot), "second lookup");
    CHECK(snapshot.proxy_config_id == 52u, "second config mismatch");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_different_local_ipv6(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY first;
    CONNECTION_KEY second;
    CONNECTION_ADDRESS destination;
    CONNECTION_SNAPSHOT snapshot;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&first, IPPROTO_UDP, AF_INET6, IPV6_A, 45000u), "first key");
    CHECK(make_key(&second, IPPROTO_UDP, AF_INET6, IPV6_B, 45000u), "second key");
    CHECK(make_address(&destination, AF_INET6, IPV6_C), "destination");
    CHECK(connection_table_upsert(
        table, &first, &destination, 53u, 61u, TRUE, 1u), "first insert");
    CHECK(connection_table_upsert(
        table, &second, &destination, 53u, 62u, TRUE, 2u), "second insert");
    CHECK(connection_table_count(table) == 2u, "IPv6 addresses collapsed");
    CHECK(connection_table_get_full(table, &first, 3u, &snapshot), "first lookup");
    CHECK(snapshot.proxy_config_id == 61u, "first config mismatch");
    CHECK(connection_table_get_full(table, &second, 4u, &snapshot), "second lookup");
    CHECK(snapshot.proxy_config_id == 62u, "second config mismatch");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_exact_update(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY key;
    CONNECTION_ADDRESS first_destination;
    CONNECTION_ADDRESS second_destination;
    CONNECTION_SNAPSHOT snapshot;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&key, IPPROTO_TCP, AF_INET, IPV4_A, 46000u), "key");
    CHECK(make_address(&first_destination, AF_INET, IPV4_C), "first destination");
    CHECK(make_address(&second_destination, AF_INET, IPV4_D), "second destination");
    CHECK(connection_table_upsert(
        table, &key, &first_destination, 80u, 71u, FALSE, 1u), "first upsert");
    CHECK(!connection_table_is_tracked(table, &key), "tracked flag not false");
    CHECK(connection_table_upsert(
        table, &key, &second_destination, 443u, 72u, TRUE, 2u), "second upsert");
    CHECK(connection_table_count(table) == 1u, "update added a node");
    CHECK(connection_table_is_tracked(table, &key), "tracked flag not updated");
    CHECK(connection_table_get_full(table, &key, 3u, &snapshot), "lookup");
    CHECK(snapshot_equal(&snapshot, AF_INET, IPV4_D, 443u, 72u), "update mismatch");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_one_field_difference(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY keys[5];
    CONNECTION_ADDRESS destination4;
    CONNECTION_ADDRESS destination6;
    CONNECTION_SNAPSHOT snapshot;
    SIZE_T index;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&keys[0], IPPROTO_TCP, AF_INET, IPV4_A, 47000u), "base key");
    CHECK(make_key(&keys[1], IPPROTO_UDP, AF_INET, IPV4_A, 47000u), "protocol key");
    CHECK(make_key(&keys[2], IPPROTO_TCP, AF_INET6, IPV6_A, 47000u), "family key");
    CHECK(make_key(&keys[3], IPPROTO_TCP, AF_INET, IPV4_B, 47000u), "address key");
    CHECK(make_key(&keys[4], IPPROTO_TCP, AF_INET, IPV4_A, 47001u), "port key");
    CHECK(make_address(&destination4, AF_INET, IPV4_C), "IPv4 destination");
    CHECK(make_address(&destination6, AF_INET6, IPV6_C), "IPv6 destination");

    for (index = 0u; index < ARRAY_COUNT(keys); ++index) {
        CONNECTION_ADDRESS *destination =
            keys[index].family == AF_INET ? &destination4 : &destination6;

        CHECK(connection_table_upsert(
            table,
            &keys[index],
            destination,
            (UINT16)(5000u + index),
            (UINT32)(80u + index),
            TRUE,
            (ULONGLONG)index), "insert one-field key");
    }

    CHECK(connection_table_count(table) == ARRAY_COUNT(keys), "one field ignored");
    for (index = 0u; index < ARRAY_COUNT(keys); ++index) {
        CHECK(connection_table_get_full(
            table, &keys[index], 100u + index, &snapshot), "lookup one-field key");
        CHECK(snapshot.proxy_config_id == 80u + index, "wrong one-field entry");
    }

    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_remove_tcp_preserves_udp(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY tcp_key;
    CONNECTION_KEY udp_key;
    CONNECTION_ADDRESS destination;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&tcp_key, IPPROTO_TCP, AF_INET, IPV4_A, 48000u), "TCP key");
    CHECK(make_key(&udp_key, IPPROTO_UDP, AF_INET, IPV4_A, 48000u), "UDP key");
    CHECK(make_address(&destination, AF_INET, IPV4_C), "destination");
    CHECK(connection_table_upsert(
        table, &tcp_key, &destination, 443u, 91u, TRUE, 1u), "insert TCP");
    CHECK(connection_table_upsert(
        table, &udp_key, &destination, 443u, 92u, TRUE, 2u), "insert UDP");
    CHECK(connection_table_remove(table, &tcp_key), "remove TCP");
    CHECK(!connection_table_is_tracked(table, &tcp_key), "TCP remains");
    CHECK(connection_table_is_tracked(table, &udp_key), "UDP was removed");
    CHECK(connection_table_count(table) == 1u, "wrong count after removal");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_remove_family_address_preserves_other(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY ipv4_a;
    CONNECTION_KEY ipv4_b;
    CONNECTION_KEY ipv6;
    CONNECTION_ADDRESS destination4;
    CONNECTION_ADDRESS destination6;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&ipv4_a, IPPROTO_TCP, AF_INET, IPV4_A, 49000u), "IPv4 A key");
    CHECK(make_key(&ipv4_b, IPPROTO_TCP, AF_INET, IPV4_B, 49000u), "IPv4 B key");
    CHECK(make_key(&ipv6, IPPROTO_TCP, AF_INET6, IPV6_A, 49000u), "IPv6 key");
    CHECK(make_address(&destination4, AF_INET, IPV4_C), "IPv4 destination");
    CHECK(make_address(&destination6, AF_INET6, IPV6_C), "IPv6 destination");
    CHECK(connection_table_upsert(
        table, &ipv4_a, &destination4, 80u, 101u, TRUE, 1u), "insert IPv4 A");
    CHECK(connection_table_upsert(
        table, &ipv4_b, &destination4, 80u, 102u, TRUE, 2u), "insert IPv4 B");
    CHECK(connection_table_upsert(
        table, &ipv6, &destination6, 80u, 103u, TRUE, 3u), "insert IPv6");
    CHECK(connection_table_remove(table, &ipv4_a), "remove IPv4 A");
    CHECK(connection_table_is_tracked(table, &ipv4_b), "IPv4 B was removed");
    CHECK(connection_table_is_tracked(table, &ipv6), "IPv6 was removed");
    CHECK(connection_table_count(table) == 2u, "wrong count after first removal");
    CHECK(connection_table_remove(table, &ipv6), "remove IPv6");
    CHECK(connection_table_is_tracked(table, &ipv4_b), "IPv4 B lost after IPv6 removal");
    CHECK(connection_table_count(table) == 1u, "wrong count after second removal");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_cleanup_stale_fresh_same_bucket(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY keys[2];
    CONNECTION_ADDRESS destination;

    CHECK(table != NULL, "table allocation failed");
    CHECK(find_ipv4_keys_in_one_bucket(keys, ARRAY_COUNT(keys), IPPROTO_TCP),
          "no collision pair found");
    CHECK(make_address(&destination, AF_INET, IPV4_C), "destination");
    CHECK(connection_table_upsert(
        table, &keys[0], &destination, 80u, 111u, TRUE, 10u), "insert stale");
    CHECK(connection_table_upsert(
        table, &keys[1], &destination, 80u, 112u, TRUE, 95u), "insert fresh");
    CHECK(connection_table_cleanup(table, 100u, 20u) == 1u, "cleanup count");
    CHECK(!connection_table_is_tracked(table, &keys[0]), "stale entry remains");
    CHECK(connection_table_is_tracked(table, &keys[1]), "fresh entry removed");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_deliberate_hash_collision(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY keys[2];
    CONNECTION_ADDRESS first_destination;
    CONNECTION_ADDRESS second_destination;
    CONNECTION_SNAPSHOT snapshot;
    UINT32 first_bucket;
    UINT32 second_bucket;

    CHECK(table != NULL, "table allocation failed");
    CHECK(find_ipv4_keys_in_one_bucket(keys, ARRAY_COUNT(keys), IPPROTO_UDP),
          "no collision pair found");
    CHECK(connection_key_bucket_index(&keys[0], &first_bucket), "first bucket");
    CHECK(connection_key_bucket_index(&keys[1], &second_bucket), "second bucket");
    CHECK(first_bucket == second_bucket, "helper did not make a collision");
    CHECK(!key_equal(&keys[0], &keys[1]), "collision keys are identical");
    CHECK(make_address(&first_destination, AF_INET, IPV4_C), "first destination");
    CHECK(make_address(&second_destination, AF_INET, IPV4_D), "second destination");
    CHECK(connection_table_upsert(
        table, &keys[0], &first_destination, 1000u, 121u, TRUE, 1u), "first insert");
    CHECK(connection_table_upsert(
        table, &keys[1], &second_destination, 2000u, 122u, TRUE, 2u), "second insert");
    CHECK(connection_table_get_full(table, &keys[0], 3u, &snapshot), "first lookup");
    CHECK(snapshot_equal(
        &snapshot, AF_INET, IPV4_C, 1000u, 121u), "first collision mismatch");
    CHECK(connection_table_get_full(table, &keys[1], 4u, &snapshot), "second lookup");
    CHECK(snapshot_equal(
        &snapshot, AF_INET, IPV4_D, 2000u, 122u), "second collision mismatch");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_clear_and_reuse(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY key;
    CONNECTION_ADDRESS destination;
    CONNECTION_SNAPSHOT snapshot;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&key, IPPROTO_TCP, AF_INET, IPV4_A, 50000u), "key");
    CHECK(make_address(&destination, AF_INET, IPV4_C), "destination");
    CHECK(connection_table_upsert(
        table, &key, &destination, 80u, 131u, TRUE, 1u), "first insert");
    CHECK(connection_table_clear(table) == 1u, "clear count");
    CHECK(connection_table_count(table) == 0u, "table not empty");
    CHECK(!connection_table_get_full(table, &key, 2u, &snapshot), "cleared key found");
    CHECK(connection_table_upsert(
        table, &key, &destination, 443u, 132u, TRUE, 3u), "reuse insert");
    CHECK(connection_table_get_full(table, &key, 4u, &snapshot), "reuse lookup");
    CHECK(snapshot.destination_port == 443u &&
          snapshot.proxy_config_id == 132u, "reuse value mismatch");
    connection_table_destroy(table);
    return TRUE;
}

typedef struct SNAPSHOT_TEST_CONTEXT {
    CONNECTION_TABLE *table;
    CONNECTION_KEY key;
    CONNECTION_ADDRESS destination_a;
    CONNECTION_ADDRESS destination_b;
    volatile LONG failed;
} SNAPSHOT_TEST_CONTEXT;

static DWORD WINAPI snapshot_writer(LPVOID parameter)
{
    SNAPSHOT_TEST_CONTEXT *context =
        (SNAPSHOT_TEST_CONTEXT *)parameter;
    UINT32 iteration;

    for (iteration = 0u; iteration < 10000u; ++iteration) {
        BOOL use_a = (iteration & 1u) == 0u;

        if (!connection_table_upsert_decision(
                context->table,
                &context->key,
                use_a ? &context->destination_a : &context->destination_b,
                use_a ? 1001u : 2002u,
                use_a ? 141u : 142u,
                TRUE,
                use_a ? CONNECTION_DECISION_DIRECT : CONNECTION_DECISION_PROXY,
                iteration)) {
            InterlockedExchange(&context->failed, 1);
            break;
        }
    }

    return 0u;
}

static DWORD WINAPI snapshot_reader(LPVOID parameter)
{
    SNAPSHOT_TEST_CONTEXT *context =
        (SNAPSHOT_TEST_CONTEXT *)parameter;
    UINT32 iteration;

    for (iteration = 0u; iteration < 10000u; ++iteration) {
        CONNECTION_SNAPSHOT snapshot;
        BOOL is_a;
        BOOL is_b;

        if (!connection_table_get_full(
                context->table,
                &context->key,
                20000u + iteration,
                &snapshot)) {
            InterlockedExchange(&context->failed, 1);
            break;
        }

        is_a = snapshot_equal_decision(
            &snapshot,
            AF_INET,
            IPV4_C,
            1001u,
            141u,
            CONNECTION_DECISION_DIRECT);
        is_b = snapshot_equal_decision(
            &snapshot,
            AF_INET,
            IPV4_D,
            2002u,
            142u,
            CONNECTION_DECISION_PROXY);
        if (!is_a && !is_b) {
            InterlockedExchange(&context->failed, 1);
            break;
        }
    }

    return 0u;
}

static BOOL test_consistent_snapshot(void)
{
    SNAPSHOT_TEST_CONTEXT context;
    HANDLE writer;
    HANDLE reader;
    HANDLE threads[2];

    memset(&context, 0, sizeof(context));
    context.table = connection_table_create();
    CHECK(context.table != NULL, "table allocation failed");
    CHECK(make_key(
        &context.key, IPPROTO_TCP, AF_INET, IPV4_A, 51000u), "key");
    CHECK(make_address(
        &context.destination_a, AF_INET, IPV4_C), "destination A");
    CHECK(make_address(
        &context.destination_b, AF_INET, IPV4_D), "destination B");
    CHECK(connection_table_upsert_decision(
        context.table,
        &context.key,
        &context.destination_a,
        1001u,
        141u,
        TRUE,
        CONNECTION_DECISION_DIRECT,
        1u), "initial insert");

    writer = CreateThread(NULL, 0u, snapshot_writer, &context, 0u, NULL);
    CHECK(writer != NULL, "writer thread creation failed");
    reader = CreateThread(NULL, 0u, snapshot_reader, &context, 0u, NULL);
    if (reader == NULL) {
        (void)WaitForSingleObject(writer, INFINITE);
        CloseHandle(writer);
        connection_table_destroy(context.table);
        return test_failure(
            __func__, __LINE__, "reader != NULL", "reader thread creation failed");
    }

    threads[0] = writer;
    threads[1] = reader;
    CHECK(WaitForMultipleObjects(
        (DWORD)ARRAY_COUNT(threads), threads, TRUE, INFINITE) == WAIT_OBJECT_0,
        "thread wait failed");
    CloseHandle(reader);
    CloseHandle(writer);
    CHECK(InterlockedCompareExchange(&context.failed, 0, 0) == 0,
          "observed torn or missing snapshot");
    connection_table_destroy(context.table);
    return TRUE;
}

static BOOL test_reverse_udp_filtering(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY wanted;
    CONNECTION_KEY tcp;
    CONNECTION_KEY other_config;
    CONNECTION_KEY other_address;
    CONNECTION_KEY other_port;
    CONNECTION_KEY other_family;
    CONNECTION_KEY found;
    CONNECTION_ADDRESS destination4;
    CONNECTION_ADDRESS other_destination4;
    CONNECTION_ADDRESS destination6;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&wanted, IPPROTO_UDP, AF_INET, IPV4_A, 52000u), "wanted key");
    CHECK(make_key(&tcp, IPPROTO_TCP, AF_INET, IPV4_A, 52000u), "TCP key");
    CHECK(make_key(&other_config, IPPROTO_UDP, AF_INET, IPV4_A, 52001u),
          "other config key");
    CHECK(make_key(&other_address, IPPROTO_UDP, AF_INET, IPV4_A, 52002u),
          "other address key");
    CHECK(make_key(&other_port, IPPROTO_UDP, AF_INET, IPV4_A, 52003u),
          "other port key");
    CHECK(make_key(&other_family, IPPROTO_UDP, AF_INET6, IPV6_A, 52000u),
          "other family key");
    CHECK(make_address(&destination4, AF_INET, IPV4_C), "destination IPv4");
    CHECK(make_address(&other_destination4, AF_INET, IPV4_D), "other IPv4");
    CHECK(make_address(&destination6, AF_INET6, IPV6_C), "destination IPv6");

    CHECK(connection_table_upsert(
        table, &wanted, &destination4, 5300u, 151u, TRUE, 10u), "wanted insert");
    CHECK(connection_table_upsert(
        table, &tcp, &destination4, 5300u, 151u, TRUE, 99u), "TCP insert");
    CHECK(connection_table_upsert(
        table, &other_config, &destination4, 5300u, 152u, TRUE, 98u),
        "other config insert");
    CHECK(connection_table_upsert(
        table, &other_address, &other_destination4, 5300u, 151u, TRUE, 97u),
        "other address insert");
    CHECK(connection_table_upsert(
        table, &other_port, &destination4, 5301u, 151u, TRUE, 96u),
        "other port insert");
    CHECK(connection_table_upsert(
        table, &other_family, &destination6, 5300u, 151u, TRUE, 95u),
        "other family insert");
    CHECK(connection_table_find_udp_sender(
        table, AF_INET, 151u, &destination4, 5300u, &found), "reverse lookup");
    CHECK(key_equal(&found, &wanted), "reverse filters selected wrong key");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_reverse_udp_newest(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY older;
    CONNECTION_KEY newer;
    CONNECTION_KEY found;
    CONNECTION_ADDRESS destination;
    CONNECTION_SNAPSHOT snapshot;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&older, IPPROTO_UDP, AF_INET, IPV4_A, 53000u), "older key");
    CHECK(make_key(&newer, IPPROTO_UDP, AF_INET, IPV4_B, 53001u), "newer key");
    CHECK(make_address(&destination, AF_INET, IPV4_C), "destination");
    CHECK(connection_table_upsert(
        table, &older, &destination, 5353u, 161u, TRUE, 10u), "older insert");
    CHECK(connection_table_upsert(
        table, &newer, &destination, 5353u, 161u, TRUE, 20u), "newer insert");
    CHECK(connection_table_find_udp_sender(
        table, AF_INET, 161u, &destination, 5353u, &found), "first reverse lookup");
    CHECK(key_equal(&found, &newer), "newest entry not selected");
    CHECK(connection_table_get_full(
        table, &older, 30u, &snapshot), "touch older entry");
    CHECK(connection_table_find_udp_sender(
        table, AF_INET, 161u, &destination, 5353u, &found), "second reverse lookup");
    CHECK(key_equal(&found, &older), "activity update not observed");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_get_full_timestamp_regression(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY key_a;
    CONNECTION_KEY key_b;
    CONNECTION_KEY found;
    CONNECTION_ADDRESS destination;
    CONNECTION_SNAPSHOT snapshot;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&key_a, IPPROTO_UDP, AF_INET, IPV4_A, 57000u), "key A");
    CHECK(make_key(&key_b, IPPROTO_UDP, AF_INET, IPV4_B, 57001u), "key B");
    CHECK(make_address(&destination, AF_INET, IPV4_C), "destination");
    CHECK(connection_table_upsert(
        table, &key_a, &destination, 5454u, 191u, TRUE, 100u), "insert A");
    CHECK(connection_table_upsert(
        table, &key_b, &destination, 5454u, 191u, TRUE, 90u), "insert B");
    CHECK(connection_table_get_full(
        table, &key_a, 80u, &snapshot), "regressing get_full failed");
    CHECK(connection_table_find_udp_sender(
        table, AF_INET, 191u, &destination, 5454u, &found),
        "reverse lookup after regressing get_full");
    CHECK(key_equal(&found, &key_a),
          "get_full reduced activity and changed reverse-newest selection");
    CHECK(connection_table_cleanup(table, 111u, 20u) == 1u,
          "cleanup did not preserve activity=100 boundary");
    CHECK(connection_table_is_tracked(table, &key_a),
          "entry A was removed as if activity had regressed to 80");
    CHECK(connection_table_count(table) == 1u,
          "cleanup did not remove only the activity=90 entry");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_upsert_timestamp_regression(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY key_a;
    CONNECTION_KEY key_b;
    CONNECTION_KEY found;
    CONNECTION_ADDRESS first_destination;
    CONNECTION_ADDRESS updated_destination;
    CONNECTION_SNAPSHOT snapshot;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&key_a, IPPROTO_UDP, AF_INET, IPV4_A, 58000u), "key A");
    CHECK(make_key(&key_b, IPPROTO_UDP, AF_INET, IPV4_B, 58001u), "key B");
    CHECK(make_address(&first_destination, AF_INET, IPV4_C),
          "first destination");
    CHECK(make_address(&updated_destination, AF_INET, IPV4_D),
          "updated destination");
    CHECK(connection_table_upsert(
        table,
        &key_a,
        &first_destination,
        6000u,
        201u,
        FALSE,
        100u), "initial insert A");
    CHECK(connection_table_upsert(
        table,
        &key_a,
        &updated_destination,
        6001u,
        202u,
        TRUE,
        70u), "regressing exact-key upsert");
    CHECK(connection_table_count(table) == 1u,
          "exact-key update created a new node");
    CHECK(connection_table_is_tracked(table, &key_a),
          "exact-key update did not update tracked payload");
    CHECK(connection_table_get_full(
        table, &key_a, 70u, &snapshot), "updated snapshot lookup");
    CHECK(snapshot_equal(
        &snapshot, AF_INET, IPV4_D, 6001u, 202u),
        "exact-key update did not update routing payload");
    CHECK(connection_table_upsert(
        table,
        &key_b,
        &updated_destination,
        6001u,
        202u,
        TRUE,
        90u), "insert comparison entry B");
    CHECK(connection_table_find_udp_sender(
        table, AF_INET, 202u, &updated_destination, 6001u, &found),
        "reverse lookup after regressing upsert");
    CHECK(key_equal(&found, &key_a),
          "upsert reduced activity while updating routing payload");
    CHECK(connection_table_cleanup(table, 111u, 20u) == 1u,
          "cleanup did not preserve upsert activity=100 boundary");
    CHECK(connection_table_is_tracked(table, &key_a),
          "updated entry was removed as if activity had regressed to 70");
    connection_table_destroy(table);
    return TRUE;
}

typedef struct MONOTONIC_TOUCH_CONTEXT {
    CONNECTION_TABLE *table;
    const CONNECTION_KEY *key;
    ULONGLONG timestamp;
    HANDLE start_event;
    HANDLE done_event;
    volatile LONG failed;
} MONOTONIC_TOUCH_CONTEXT;

static DWORD WINAPI monotonic_touch_thread(LPVOID parameter)
{
    MONOTONIC_TOUCH_CONTEXT *context =
        (MONOTONIC_TOUCH_CONTEXT *)parameter;
    CONNECTION_SNAPSHOT snapshot;

    if (WaitForSingleObject(context->start_event, INFINITE) != WAIT_OBJECT_0 ||
        !connection_table_get_full(
            context->table,
            context->key,
            context->timestamp,
            &snapshot)) {
        InterlockedExchange(&context->failed, 1);
    }

    if (!SetEvent(context->done_event)) {
        InterlockedExchange(&context->failed, 1);
    }

    return 0u;
}

static BOOL test_concurrent_monotonic_touch(void)
{
    static const ULONGLONG timestamps[4] = {
        200u, 150u, 175u, 125u
    };
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY key_a;
    CONNECTION_KEY key_b;
    CONNECTION_KEY found;
    CONNECTION_ADDRESS destination;
    MONOTONIC_TOUCH_CONTEXT contexts[ARRAY_COUNT(timestamps)];
    HANDLE start_events[ARRAY_COUNT(timestamps)];
    HANDLE done_events[ARRAY_COUNT(timestamps)];
    HANDLE threads[ARRAY_COUNT(timestamps)];
    SIZE_T index;

    memset(contexts, 0, sizeof(contexts));
    memset(start_events, 0, sizeof(start_events));
    memset(done_events, 0, sizeof(done_events));
    memset(threads, 0, sizeof(threads));

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&key_a, IPPROTO_UDP, AF_INET, IPV4_A, 59000u), "key A");
    CHECK(make_key(&key_b, IPPROTO_UDP, AF_INET, IPV4_B, 59001u), "key B");
    CHECK(make_address(&destination, AF_INET, IPV4_C), "destination");
    CHECK(connection_table_upsert(
        table, &key_a, &destination, 6464u, 211u, TRUE, 100u), "insert A");
    CHECK(connection_table_upsert(
        table, &key_b, &destination, 6464u, 211u, TRUE, 199u), "insert B");

    for (index = 0u; index < ARRAY_COUNT(timestamps); ++index) {
        start_events[index] = CreateEvent(NULL, TRUE, FALSE, NULL);
        done_events[index] = CreateEvent(NULL, TRUE, FALSE, NULL);
        CHECK(start_events[index] != NULL && done_events[index] != NULL,
              "monotonic touch event creation failed");
        contexts[index].table = table;
        contexts[index].key = &key_a;
        contexts[index].timestamp = timestamps[index];
        contexts[index].start_event = start_events[index];
        contexts[index].done_event = done_events[index];
        threads[index] = CreateThread(
            NULL,
            0u,
            monotonic_touch_thread,
            &contexts[index],
            0u,
            NULL);
        CHECK(threads[index] != NULL,
              "monotonic touch thread creation failed");
    }

    CHECK(SetEvent(start_events[0]), "maximum timestamp start failed");
    CHECK(WaitForSingleObject(done_events[0], INFINITE) == WAIT_OBJECT_0,
          "maximum timestamp touch did not complete");

    for (index = 1u; index < ARRAY_COUNT(timestamps); ++index) {
        CHECK(SetEvent(start_events[index]), "lower timestamp start failed");
    }
    CHECK(WaitForMultipleObjects(
        (DWORD)(ARRAY_COUNT(timestamps) - 1u),
        &done_events[1],
        TRUE,
        INFINITE) == WAIT_OBJECT_0, "lower timestamp touches did not complete");
    CHECK(WaitForMultipleObjects(
        (DWORD)ARRAY_COUNT(threads),
        threads,
        TRUE,
        INFINITE) == WAIT_OBJECT_0, "monotonic touch threads did not exit");

    for (index = 0u; index < ARRAY_COUNT(timestamps); ++index) {
        CHECK(InterlockedCompareExchange(
            &contexts[index].failed, 0, 0) == 0,
            "a concurrent get_full operation failed");
        CloseHandle(threads[index]);
        CloseHandle(done_events[index]);
        CloseHandle(start_events[index]);
    }

    CHECK(connection_table_find_udp_sender(
        table, AF_INET, 211u, &destination, 6464u, &found),
        "reverse lookup after concurrent touches");
    CHECK(key_equal(&found, &key_a),
          "a lower concurrent timestamp replaced the completed maximum");
    CHECK(connection_table_cleanup(table, 211u, 11u) == 1u,
          "cleanup boundary did not observe maximum timestamp=200");
    CHECK(connection_table_is_tracked(table, &key_a),
          "maximum timestamp entry was removed after concurrent touches");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_equal_timestamp(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY key;
    CONNECTION_ADDRESS destination;
    CONNECTION_SNAPSHOT first_snapshot;
    CONNECTION_SNAPSHOT second_snapshot;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&key, IPPROTO_UDP, AF_INET, IPV4_A, 60000u), "key");
    CHECK(make_address(&destination, AF_INET, IPV4_D), "destination");
    CHECK(connection_table_upsert(
        table, &key, &destination, 7474u, 221u, TRUE, 300u), "insert");
    CHECK(connection_table_get_full(
        table, &key, 300u, &first_snapshot), "first equal timestamp touch");
    CHECK(connection_table_get_full(
        table, &key, 300u, &second_snapshot), "second equal timestamp touch");
    CHECK(snapshot_equal(
        &first_snapshot, AF_INET, IPV4_D, 7474u, 221u),
        "first equal touch changed routing snapshot");
    CHECK(snapshot_equal(
        &second_snapshot, AF_INET, IPV4_D, 7474u, 221u),
        "second equal touch changed routing snapshot");
    CHECK(connection_table_count(table) == 1u,
          "equal timestamp touch created a new node");
    CHECK(connection_table_cleanup(table, 311u, 11u) == 0u,
          "equal timestamp touch corrupted activity boundary");
    CHECK(connection_table_is_tracked(table, &key),
          "equal timestamp entry was unexpectedly removed");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_invalid_protocol_family(void)
{
    CONNECTION_KEY key;
    UINT32 bucket = 123u;

    CHECK(!connection_key_set(
        &key, IPPROTO_ICMP, AF_INET, IPV4_A, sizeof(IPV4_A), 54000u),
        "invalid protocol accepted");
    CHECK(key.protocol == 0u && key.family == 0 && key.source_port == 0u,
          "failed key was not cleared");
    CHECK(!connection_key_set(
        &key, IPPROTO_TCP, AF_UNSPEC, IPV4_A, sizeof(IPV4_A), 54000u),
        "invalid family accepted");
    CHECK(!connection_key_set(
        &key, IPPROTO_TCP, AF_INET, IPV4_A, sizeof(IPV4_A) - 1u, 54000u),
        "invalid IPv4 length accepted");
    memset(&key, 0, sizeof(key));
    key.protocol = (UINT8)IPPROTO_TCP;
    key.family = AF_UNSPEC;
    CHECK(!connection_key_bucket_index(&key, &bucket), "malformed key hashed");
    CHECK(bucket == 0u, "failed bucket output not cleared");
    return TRUE;
}

static BOOL test_null_invalid_arguments(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY key;
    CONNECTION_KEY found;
    CONNECTION_ADDRESS destination;
    CONNECTION_SNAPSHOT snapshot;
    UINT32 bucket = 1u;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&key, IPPROTO_TCP, AF_INET, IPV4_A, 55000u), "key");
    CHECK(make_address(&destination, AF_INET, IPV4_C), "destination");
    CHECK(!connection_address_set(NULL, AF_INET, IPV4_A, sizeof(IPV4_A)),
          "NULL address accepted");
    CHECK(!connection_key_set(
        NULL, IPPROTO_TCP, AF_INET, IPV4_A, sizeof(IPV4_A), 1u),
        "NULL key accepted");
    CHECK(!connection_key_bucket_index(NULL, &bucket), "NULL key hashed");
    CHECK(!connection_key_bucket_index(&key, NULL), "NULL bucket accepted");
    CHECK(!connection_table_upsert(
        NULL, &key, &destination, 1u, 1u, TRUE, 1u), "NULL table upsert");
    CHECK(!connection_table_upsert(
        table, &key, NULL, 1u, 1u, TRUE, 1u), "NULL destination upsert");
    CHECK(!connection_table_is_tracked(NULL, &key), "NULL table tracked");
    CHECK(!connection_table_is_tracked(table, NULL), "NULL key tracked");
    CHECK(!connection_table_get_full(
        table, &key, 1u, NULL), "NULL snapshot accepted");
    memset(&snapshot, 0xa5, sizeof(snapshot));
    CHECK(!connection_table_get_full(
        NULL, &key, 1u, &snapshot), "NULL table lookup");
    CHECK(snapshot.family == 0 &&
          snapshot.destination_port == 0u &&
          snapshot.proxy_config_id == 0u, "failed snapshot not cleared");
    CHECK(!connection_table_remove(NULL, &key), "NULL table remove");
    CHECK(!connection_table_remove(table, NULL), "NULL key remove");
    CHECK(connection_table_cleanup(NULL, 1u, 1u) == 0u, "NULL cleanup");
    CHECK(connection_table_clear(NULL) == 0u, "NULL clear");
    CHECK(connection_table_count(NULL) == 0u, "NULL count");
    CHECK(!connection_table_find_udp_sender(
        table, AF_INET, 1u, &destination, 1u, NULL), "NULL output accepted");
    memset(&found, 0xa5, sizeof(found));
    CHECK(!connection_table_find_udp_sender(
        NULL, AF_INET, 1u, &destination, 1u, &found), "NULL reverse table");
    CHECK(found.protocol == 0u && found.family == 0 &&
          found.source_port == 0u, "failed reverse output not cleared");
    connection_table_destroy(table);
    connection_table_destroy(NULL);
    return TRUE;
}

static BOOL test_cleanup_bucket_chain(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY keys[4];
    CONNECTION_ADDRESS destination;

    CHECK(table != NULL, "table allocation failed");
    CHECK(find_ipv4_keys_in_one_bucket(keys, ARRAY_COUNT(keys), IPPROTO_TCP),
          "no four-key collision found");
    CHECK(make_address(&destination, AF_INET, IPV4_C), "destination");

    CHECK(connection_table_upsert(
        table, &keys[0], &destination, 80u, 171u, TRUE, 1u), "stale tail insert");
    CHECK(connection_table_upsert(
        table, &keys[1], &destination, 80u, 172u, TRUE, 95u), "fresh insert");
    CHECK(connection_table_upsert(
        table, &keys[2], &destination, 80u, 173u, TRUE, 2u), "stale middle insert");
    CHECK(connection_table_upsert(
        table, &keys[3], &destination, 80u, 174u, TRUE, 3u), "stale head insert");
    CHECK(connection_table_cleanup(table, 100u, 20u) == 3u, "cleanup removed count");
    CHECK(connection_table_count(table) == 1u, "cleanup survivor count");
    CHECK(!connection_table_is_tracked(table, &keys[0]), "stale tail remains");
    CHECK(connection_table_is_tracked(table, &keys[1]), "fresh entry removed");
    CHECK(!connection_table_is_tracked(table, &keys[2]), "stale middle remains");
    CHECK(!connection_table_is_tracked(table, &keys[3]), "stale head remains");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_repeated_lifecycle(void)
{
    UINT32 iteration;

    for (iteration = 0u; iteration < 100u; ++iteration) {
        CONNECTION_TABLE *table = connection_table_create();
        CONNECTION_KEY key;
        CONNECTION_ADDRESS destination;
        CONNECTION_SNAPSHOT snapshot;

        CHECK(table != NULL, "table allocation failed");
        CHECK(make_key(
            &key,
            (iteration & 1u) == 0u ? IPPROTO_TCP : IPPROTO_UDP,
            AF_INET,
            IPV4_A,
            (UINT16)(56000u + iteration)), "lifecycle key");
        CHECK(make_address(&destination, AF_INET, IPV4_C), "destination");
        CHECK(connection_table_upsert(
            table,
            &key,
            &destination,
            (UINT16)(6000u + iteration),
            180u + iteration,
            TRUE,
            iteration), "lifecycle insert");
        CHECK(connection_table_get_full(
            table, &key, 1000u + iteration, &snapshot), "lifecycle lookup");
        CHECK(connection_table_remove(table, &key), "lifecycle remove");
        CHECK(connection_table_count(table) == 0u, "lifecycle not empty");
        CHECK(connection_table_upsert(
            table,
            &key,
            &destination,
            7000u,
            280u + iteration,
            TRUE,
            iteration), "lifecycle reuse insert");
        CHECK(connection_table_clear(table) == 1u, "lifecycle clear");
        connection_table_destroy(table);
    }

    return TRUE;
}

static BOOL test_touch_tracked_updates_activity(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY key;
    CONNECTION_ADDRESS destination;
    CONNECTION_SNAPSHOT before;
    CONNECTION_SNAPSHOT after;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&key, IPPROTO_TCP, AF_INET, IPV4_A, 61000u), "key");
    CHECK(make_address(&destination, AF_INET, IPV4_C), "destination");
    CHECK(connection_table_upsert(
        table, &key, &destination, 8080u, 301u, TRUE, 100u), "insert");
    CHECK(connection_table_get_full(table, &key, 0u, &before), "before snapshot");
    CHECK(connection_table_count(table) == 1u, "initial count");

    CHECK(connection_table_touch_tracked(table, &key, 150u), "tracked touch");
    CHECK(connection_table_count(table) == 1u, "touch changed count");
    CHECK(connection_table_get_full(table, &key, 0u, &after), "after snapshot");
    CHECK(snapshot_equal(&before, AF_INET, IPV4_C, 8080u, 301u),
          "before routing snapshot mismatch");
    CHECK(snapshot_equal(&after, AF_INET, IPV4_C, 8080u, 301u),
          "touch changed routing snapshot");
    CHECK(connection_table_cleanup(table, 170u, 20u) == 0u,
          "activity=150 equality boundary removed entry");
    CHECK(connection_table_count(table) == 1u, "boundary survivor missing");
    CHECK(connection_table_cleanup(table, 171u, 20u) == 1u,
          "activity=150 stale boundary did not remove entry");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_touch_tracked_monotonic_older_and_equal(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY key;
    CONNECTION_ADDRESS destination;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&key, IPPROTO_UDP, AF_INET, IPV4_A, 61001u), "key");
    CHECK(make_address(&destination, AF_INET, IPV4_D), "destination");
    CHECK(connection_table_upsert(
        table, &key, &destination, 5353u, 302u, TRUE, 200u), "insert");

    CHECK(connection_table_touch_tracked(table, &key, 150u), "older touch");
    CHECK(connection_table_touch_tracked(table, &key, 200u), "equal touch");
    CHECK(connection_table_touch_tracked(table, &key, 0u), "zero touch");
    CHECK(connection_table_count(table) == 1u, "touch changed count");
    CHECK(connection_table_cleanup(table, 220u, 20u) == 0u,
          "activity=200 equality boundary removed entry");
    CHECK(connection_table_cleanup(table, 221u, 20u) == 1u,
          "older/equal touch increased or reduced activity");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_touch_tracked_rejects_untracked_without_mutation(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY key;
    CONNECTION_ADDRESS first_destination;
    CONNECTION_ADDRESS second_destination;
    CONNECTION_SNAPSHOT before;
    CONNECTION_SNAPSHOT after;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&key, IPPROTO_UDP, AF_INET, IPV4_A, 61002u), "key");
    CHECK(make_address(&first_destination, AF_INET, IPV4_C), "first destination");
    CHECK(make_address(&second_destination, AF_INET, IPV4_D), "second destination");
    CHECK(connection_table_upsert(
        table, &key, &first_destination, 6000u, 303u, FALSE, 100u),
        "insert untracked");
    CHECK(connection_table_get_full(table, &key, 0u, &before), "before snapshot");
    CHECK(!connection_table_touch_tracked(table, &key, 200u),
          "untracked touch succeeded");
    CHECK(connection_table_get_full(table, &key, 0u, &after), "after snapshot");
    CHECK(snapshot_equal(&before, AF_INET, IPV4_C, 6000u, 303u),
          "before routing snapshot mismatch");
    CHECK(snapshot_equal(&after, AF_INET, IPV4_C, 6000u, 303u),
          "untracked touch changed routing payload");
    CHECK(!connection_table_is_tracked(table, &key), "untracked state changed");
    CHECK(connection_table_count(table) == 1u, "untracked touch changed count");
    CHECK(connection_table_cleanup(table, 151u, 50u) == 1u,
          "untracked touch extended activity");

    CHECK(connection_table_upsert(
        table, &key, &first_destination, 6001u, 304u, TRUE, 300u),
        "insert tracked transition source");
    CHECK(connection_table_upsert(
        table, &key, &second_destination, 6002u, 305u, FALSE, 250u),
        "transition to untracked");
    CHECK(!connection_table_is_tracked(table, &key),
          "exact update did not clear tracked state");
    CHECK(!connection_table_touch_tracked(table, &key, 400u),
          "transitioned untracked touch succeeded");
    CHECK(connection_table_get_full(table, &key, 0u, &after),
          "transition snapshot");
    CHECK(snapshot_equal(&after, AF_INET, IPV4_D, 6002u, 305u),
          "transition touch changed routing payload");
    CHECK(connection_table_cleanup(table, 450u, 50u) == 1u,
          "transitioned untracked touch extended activity");
    CHECK(connection_table_count(table) == 0u, "transition entry remains");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_touch_tracked_exact_key_isolation(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY collision_keys[2];
    CONNECTION_KEY protocol_key;
    CONNECTION_KEY family_key;
    CONNECTION_KEY address_key;
    CONNECTION_KEY port_key;
    CONNECTION_ADDRESS destination;
    UINT32 target_bucket;
    UINT32 collision_bucket;
    UINT16 different_port;

    CHECK(table != NULL, "table allocation failed");
    CHECK(find_ipv4_keys_in_one_bucket(
        collision_keys, ARRAY_COUNT(collision_keys), IPPROTO_TCP),
        "same-bucket keys");
    CHECK(connection_key_bucket_index(&collision_keys[0], &target_bucket),
          "target bucket");
    CHECK(connection_key_bucket_index(&collision_keys[1], &collision_bucket),
          "collision bucket");
    CHECK(target_bucket == collision_bucket, "keys are not in one bucket");
    CHECK(make_key(
        &protocol_key,
        IPPROTO_UDP,
        AF_INET,
        IPV4_A,
        collision_keys[0].source_port), "protocol variant");
    CHECK(make_key(
        &family_key,
        IPPROTO_TCP,
        AF_INET6,
        IPV6_A,
        collision_keys[0].source_port), "family variant");
    CHECK(make_key(
        &address_key,
        IPPROTO_TCP,
        AF_INET,
        IPV4_B,
        collision_keys[0].source_port), "address variant");
    different_port = collision_keys[0].source_port == 65535u ?
        1u : (UINT16)(collision_keys[0].source_port + 1u);
    CHECK(make_key(
        &port_key,
        IPPROTO_TCP,
        AF_INET,
        IPV4_A,
        different_port), "port variant");
    CHECK(make_address(&destination, AF_INET, IPV4_C), "destination");
    CHECK(connection_table_upsert(
        table,
        &collision_keys[0],
        &destination,
        7000u,
        306u,
        TRUE,
        100u), "insert target");

    CHECK(!connection_table_touch_tracked(table, &protocol_key, 200u),
          "protocol mismatch touched target");
    CHECK(!connection_table_touch_tracked(table, &family_key, 200u),
          "family mismatch touched target");
    CHECK(!connection_table_touch_tracked(table, &address_key, 200u),
          "address mismatch touched target");
    CHECK(!connection_table_touch_tracked(table, &port_key, 200u),
          "port mismatch touched target");
    CHECK(!connection_table_touch_tracked(table, &collision_keys[1], 200u),
          "same-bucket mismatch touched target");
    CHECK(connection_table_count(table) == 1u, "mismatch touch changed count");
    CHECK(connection_table_cleanup(table, 250u, 50u) == 1u,
          "mismatch touch extended target activity");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_touch_tracked_invalid_inputs(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY key;
    CONNECTION_KEY invalid_protocol;
    CONNECTION_KEY invalid_family;
    CONNECTION_ADDRESS destination;
    CONNECTION_SNAPSHOT before;
    CONNECTION_SNAPSHOT after;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&key, IPPROTO_TCP, AF_INET, IPV4_A, 61003u), "key");
    CHECK(make_address(&destination, AF_INET, IPV4_D), "destination");
    CHECK(connection_table_upsert(
        table, &key, &destination, 7443u, 307u, TRUE, 100u), "insert");
    CHECK(connection_table_get_full(table, &key, 0u, &before), "before snapshot");

    invalid_protocol = key;
    invalid_protocol.protocol = (UINT8)IPPROTO_ICMP;
    invalid_family = key;
    invalid_family.family = AF_UNSPEC;
    CHECK(!connection_table_touch_tracked(NULL, &key, 200u), "NULL table touch");
    CHECK(!connection_table_touch_tracked(table, NULL, 200u), "NULL key touch");
    CHECK(!connection_table_touch_tracked(table, &invalid_protocol, 200u),
          "invalid protocol touch");
    CHECK(!connection_table_touch_tracked(table, &invalid_family, 200u),
          "invalid family touch");
    CHECK(connection_table_count(table) == 1u, "invalid touch changed count");
    CHECK(connection_table_get_full(table, &key, 0u, &after), "after snapshot");
    CHECK(snapshot_equal(&before, AF_INET, IPV4_D, 7443u, 307u),
          "before routing snapshot mismatch");
    CHECK(snapshot_equal(&after, AF_INET, IPV4_D, 7443u, 307u),
          "invalid touch changed entry");
    CHECK(connection_table_is_tracked(table, &key), "invalid touch changed tracked state");
    CHECK(connection_table_cleanup(table, 250u, 50u) == 1u,
          "invalid touch extended activity");
    connection_table_destroy(table);
    return TRUE;
}

typedef struct TOUCH_TRACKED_CONTEXT {
    CONNECTION_TABLE *table;
    const CONNECTION_KEY *key;
    ULONGLONG timestamp;
    HANDLE start_event;
    volatile LONG failed;
} TOUCH_TRACKED_CONTEXT;

static DWORD WINAPI touch_tracked_thread(LPVOID parameter)
{
    TOUCH_TRACKED_CONTEXT *context =
        (TOUCH_TRACKED_CONTEXT *)parameter;

    if (WaitForSingleObject(context->start_event, INFINITE) != WAIT_OBJECT_0 ||
        !connection_table_touch_tracked(
            context->table,
            context->key,
            context->timestamp)) {
        InterlockedExchange(&context->failed, 1);
    }

    return 0u;
}

static BOOL test_touch_tracked_concurrent_cas_max(void)
{
    static const ULONGLONG timestamps[] = {
        500u, 150u, 450u, 0u, 350u, 499u, 200u, 300u
    };
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY key;
    CONNECTION_ADDRESS destination;
    CONNECTION_SNAPSHOT before;
    CONNECTION_SNAPSHOT after;
    TOUCH_TRACKED_CONTEXT contexts[ARRAY_COUNT(timestamps)];
    HANDLE threads[ARRAY_COUNT(timestamps)];
    HANDLE start_event;
    SIZE_T index;

    memset(contexts, 0, sizeof(contexts));
    memset(threads, 0, sizeof(threads));
    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&key, IPPROTO_UDP, AF_INET, IPV4_B, 61004u), "key");
    CHECK(make_address(&destination, AF_INET, IPV4_C), "destination");
    CHECK(connection_table_upsert(
        table, &key, &destination, 9000u, 308u, TRUE, 100u), "insert");
    CHECK(connection_table_get_full(table, &key, 0u, &before), "before snapshot");
    start_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    CHECK(start_event != NULL, "start event creation failed");

    for (index = 0u; index < ARRAY_COUNT(timestamps); ++index) {
        contexts[index].table = table;
        contexts[index].key = &key;
        contexts[index].timestamp = timestamps[index];
        contexts[index].start_event = start_event;
        threads[index] = CreateThread(
            NULL,
            0u,
            touch_tracked_thread,
            &contexts[index],
            0u,
            NULL);
        CHECK(threads[index] != NULL, "touch thread creation failed");
    }

    CHECK(SetEvent(start_event), "concurrent start failed");
    CHECK(WaitForMultipleObjects(
        (DWORD)ARRAY_COUNT(threads),
        threads,
        TRUE,
        INFINITE) == WAIT_OBJECT_0, "touch threads did not exit");

    for (index = 0u; index < ARRAY_COUNT(timestamps); ++index) {
        CHECK(InterlockedCompareExchange(
            &contexts[index].failed, 0, 0) == 0,
            "a concurrent tracked touch failed");
        CloseHandle(threads[index]);
    }
    CloseHandle(start_event);

    CHECK(connection_table_count(table) == 1u, "concurrent touch changed count");
    CHECK(connection_table_get_full(table, &key, 0u, &after), "after snapshot");
    CHECK(snapshot_equal(&before, AF_INET, IPV4_C, 9000u, 308u),
          "before routing snapshot mismatch");
    CHECK(snapshot_equal(&after, AF_INET, IPV4_C, 9000u, 308u),
          "concurrent touch changed routing payload");
    CHECK(connection_table_cleanup(table, 520u, 20u) == 0u,
          "concurrent maximum equality boundary removed entry");
    CHECK(connection_table_cleanup(table, 521u, 20u) == 1u,
          "concurrent maximum did not reach 500");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_decision_round_trip_and_overwrite(void)
{
    static const CONNECTION_DECISION decisions[] = {
        CONNECTION_DECISION_NONE,
        CONNECTION_DECISION_DIRECT,
        CONNECTION_DECISION_PROXY,
        CONNECTION_DECISION_BLOCK
    };
    static const BOOL tracked_values[] = {TRUE, FALSE, TRUE, FALSE};
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY key;
    CONNECTION_ADDRESS destination_a;
    CONNECTION_ADDRESS destination_b;
    CONNECTION_SNAPSHOT snapshot;
    SIZE_T index;

    CHECK(CONNECTION_DECISION_NONE == 0, "NONE value changed");
    CHECK(CONNECTION_DECISION_DIRECT == 1, "DIRECT value changed");
    CHECK(CONNECTION_DECISION_PROXY == 2, "PROXY value changed");
    CHECK(CONNECTION_DECISION_BLOCK == 3, "BLOCK value changed");
    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&key, IPPROTO_TCP, AF_INET, IPV4_A, 62000u), "key");
    CHECK(make_address(&destination_a, AF_INET, IPV4_C), "destination A");
    CHECK(make_address(&destination_b, AF_INET, IPV4_D), "destination B");

    for (index = 0u; index < ARRAY_COUNT(decisions); ++index) {
        const CONNECTION_ADDRESS *destination =
            (index & 1u) == 0u ? &destination_a : &destination_b;
        const UINT8 *destination_bytes =
            (index & 1u) == 0u ? IPV4_C : IPV4_D;
        UINT16 destination_port = (UINT16)(8100u + index);
        UINT32 proxy_config_id = 320u + (UINT32)index;

        CHECK(connection_table_upsert_decision(
            table,
            &key,
            destination,
            destination_port,
            proxy_config_id,
            tracked_values[index],
            decisions[index],
            100u + index), "decision upsert");
        CHECK(connection_table_count(table) == 1u,
              "decision overwrite created a node");
        CHECK(connection_table_get_full(table, &key, 0u, &snapshot),
              "decision snapshot");
        CHECK(snapshot_equal_decision(
            &snapshot,
            AF_INET,
            destination_bytes,
            destination_port,
            proxy_config_id,
            decisions[index]), "decision round-trip mismatch");
        CHECK(connection_table_is_tracked(table, &key) == tracked_values[index],
              "decision changed independent tracked state");
    }

    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_invalid_decision_rejected_without_mutation(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY key;
    CONNECTION_ADDRESS destination_a;
    CONNECTION_ADDRESS destination_b;
    CONNECTION_SNAPSHOT snapshot;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&key, IPPROTO_TCP, AF_INET, IPV4_A, 62001u), "key");
    CHECK(make_address(&destination_a, AF_INET, IPV4_C), "destination A");
    CHECK(make_address(&destination_b, AF_INET, IPV4_D), "destination B");
    CHECK(connection_table_upsert_decision(
        table, &key, &destination_a, 8200u, 330u, TRUE,
        CONNECTION_DECISION_DIRECT, 100u), "initial decision insert");

    CHECK(!connection_table_upsert_decision(
        table, &key, &destination_b, 8201u, 331u, FALSE,
        (CONNECTION_DECISION)4, 500u), "decision value 4 accepted");
    CHECK(!connection_table_upsert_decision(
        table, &key, &destination_b, 8202u, 332u, FALSE,
        (CONNECTION_DECISION)-1, 600u), "negative decision accepted");
    CHECK(connection_table_count(table) == 1u, "invalid decision changed count");
    CHECK(connection_table_get_full(table, &key, 0u, &snapshot), "snapshot");
    CHECK(snapshot_equal_decision(
        &snapshot, AF_INET, IPV4_C, 8200u, 330u,
        CONNECTION_DECISION_DIRECT), "invalid decision mutated value");
    CHECK(connection_table_is_tracked(table, &key),
          "invalid decision mutated tracked state");
    CHECK(connection_table_cleanup(table, 151u, 50u) == 1u,
          "invalid decision mutated activity");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_legacy_upsert_decision_none_tracked(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY key;
    CONNECTION_ADDRESS destination;
    CONNECTION_SNAPSHOT snapshot;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&key, IPPROTO_TCP, AF_INET, IPV4_A, 62002u), "key");
    CHECK(make_address(&destination, AF_INET, IPV4_C), "destination");
    CHECK(connection_table_upsert_decision(
        table, &key, &destination, 8299u, 332u, FALSE,
        CONNECTION_DECISION_DIRECT, 50u), "typed predecessor insert");
    CHECK(connection_table_upsert(
        table, &key, &destination, 8300u, 333u, TRUE, 100u),
        "legacy insert");
    CHECK(connection_table_count(table) == 1u,
          "legacy update created a node");
    CHECK(connection_table_get_full(table, &key, 0u, &snapshot),
          "legacy snapshot");
    CHECK(snapshot_equal_decision(
        &snapshot, AF_INET, IPV4_C, 8300u, 333u,
        CONNECTION_DECISION_NONE), "legacy decision is not NONE");
    CHECK(connection_table_is_tracked(table, &key),
          "legacy tracked state missing");

    memset(&snapshot, 0xa5, sizeof(snapshot));
    CHECK(!connection_table_touch_decision(
        table, &key, &destination, 8300u, 500u, &snapshot),
        "NONE decision touch succeeded");
    CHECK(snapshot.family == 0 &&
          snapshot.proxy_config_id == 0u &&
          snapshot.decision == CONNECTION_DECISION_NONE,
          "failed decision touch did not clear output");
    CHECK(connection_table_touch_tracked(table, &key, 150u),
          "legacy tracked touch failed");
    CHECK(connection_table_cleanup(table, 200u, 50u) == 0u,
          "tracked equality boundary removed entry");
    CHECK(connection_table_cleanup(table, 201u, 50u) == 1u,
          "NONE decision touch changed activity");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_decision_exact_key_separation(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY ipv4_a;
    CONNECTION_KEY ipv4_b;
    CONNECTION_KEY ipv6_a;
    CONNECTION_ADDRESS destination4_a;
    CONNECTION_ADDRESS destination4_b;
    CONNECTION_ADDRESS destination6;
    CONNECTION_SNAPSHOT snapshot;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&ipv4_a, IPPROTO_TCP, AF_INET, IPV4_A, 62003u),
          "IPv4 A key");
    CHECK(make_key(&ipv4_b, IPPROTO_TCP, AF_INET, IPV4_B, 62003u),
          "IPv4 B key");
    CHECK(make_key(&ipv6_a, IPPROTO_TCP, AF_INET6, IPV6_A, 62003u),
          "IPv6 key");
    CHECK(make_address(&destination4_a, AF_INET, IPV4_C),
          "IPv4 destination A");
    CHECK(make_address(&destination4_b, AF_INET, IPV4_D),
          "IPv4 destination B");
    CHECK(make_address(&destination6, AF_INET6, IPV6_C),
          "IPv6 destination");

    CHECK(connection_table_upsert_decision(
        table, &ipv4_a, &destination4_a, 8400u, 334u, FALSE,
        CONNECTION_DECISION_DIRECT, 100u), "IPv4 A insert");
    CHECK(connection_table_upsert_decision(
        table, &ipv4_b, &destination4_b, 8401u, 335u, FALSE,
        CONNECTION_DECISION_BLOCK, 101u), "IPv4 B insert");
    CHECK(connection_table_upsert_decision(
        table, &ipv6_a, &destination6, 8402u, 336u, TRUE,
        CONNECTION_DECISION_PROXY, 102u), "IPv6 insert");
    CHECK(connection_table_count(table) == 3u,
          "family/address-separated keys collided");

    CHECK(connection_table_touch_decision(
        table, &ipv4_a, &destination4_a, 8400u, 110u, &snapshot),
        "IPv4 A touch");
    CHECK(snapshot_equal_decision(
        &snapshot, AF_INET, IPV4_C, 8400u, 334u,
        CONNECTION_DECISION_DIRECT), "IPv4 A decision mismatch");
    CHECK(connection_table_touch_decision(
        table, &ipv4_b, &destination4_b, 8401u, 111u, &snapshot),
        "IPv4 B touch");
    CHECK(snapshot_equal_decision(
        &snapshot, AF_INET, IPV4_D, 8401u, 335u,
        CONNECTION_DECISION_BLOCK), "IPv4 B decision mismatch");
    CHECK(connection_table_touch_decision(
        table, &ipv6_a, &destination6, 8402u, 112u, &snapshot),
        "IPv6 touch");
    CHECK(snapshot_equal_decision(
        &snapshot, AF_INET6, IPV6_C, 8402u, 336u,
        CONNECTION_DECISION_PROXY), "IPv6 decision mismatch");

    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_touch_decision_full_snapshot_monotonic(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY key;
    CONNECTION_ADDRESS destination;
    CONNECTION_SNAPSHOT snapshot;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&key, IPPROTO_TCP, AF_INET, IPV4_A, 62004u), "key");
    CHECK(make_address(&destination, AF_INET, IPV4_D), "destination");
    CHECK(connection_table_upsert_decision(
        table, &key, &destination, 8500u, 337u, TRUE,
        CONNECTION_DECISION_PROXY, 200u), "insert");

    CHECK(connection_table_touch_decision(
        table, &key, &destination, 8500u, 150u, &snapshot), "older touch");
    CHECK(snapshot_equal_decision(
        &snapshot, AF_INET, IPV4_D, 8500u, 337u,
        CONNECTION_DECISION_PROXY), "older touch snapshot mismatch");
    CHECK(connection_table_touch_decision(
        table, &key, &destination, 8500u, 250u, &snapshot), "newer touch");
    CHECK(snapshot_equal_decision(
        &snapshot, AF_INET, IPV4_D, 8500u, 337u,
        CONNECTION_DECISION_PROXY), "newer touch snapshot mismatch");
    CHECK(connection_table_is_tracked(table, &key),
          "decision touch changed tracked state");
    CHECK(connection_table_cleanup(table, 270u, 20u) == 0u,
          "maximum activity equality boundary removed entry");
    CHECK(connection_table_cleanup(table, 271u, 20u) == 1u,
          "maximum activity was not 250");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_touch_decision_mismatch_and_invalid_inputs(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY key;
    CONNECTION_KEY invalid_key;
    CONNECTION_ADDRESS destination;
    CONNECTION_ADDRESS wrong_destination;
    CONNECTION_SNAPSHOT snapshot;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&key, IPPROTO_TCP, AF_INET, IPV4_A, 62005u), "key");
    CHECK(make_address(&destination, AF_INET, IPV4_C), "destination");
    CHECK(make_address(&wrong_destination, AF_INET, IPV4_D),
          "wrong destination");
    CHECK(connection_table_upsert_decision(
        table, &key, &destination, 8600u, 338u, TRUE,
        CONNECTION_DECISION_BLOCK, 100u), "insert");

    CHECK(!connection_table_touch_decision(
        table, &key, &wrong_destination, 8600u, 500u, &snapshot),
        "destination-address mismatch touched entry");
    CHECK(!connection_table_touch_decision(
        table, &key, &destination, 8601u, 500u, &snapshot),
        "destination-port mismatch touched entry");

    invalid_key = key;
    invalid_key.family = AF_UNSPEC;
    CHECK(!connection_table_touch_decision(
        NULL, &key, &destination, 8600u, 500u, &snapshot), "NULL table touch");
    CHECK(!connection_table_touch_decision(
        table, NULL, &destination, 8600u, 500u, &snapshot), "NULL key touch");
    CHECK(!connection_table_touch_decision(
        table, &key, NULL, 8600u, 500u, &snapshot), "NULL destination touch");
    CHECK(!connection_table_touch_decision(
        table, &key, &destination, 8600u, 500u, NULL), "NULL snapshot touch");
    CHECK(!connection_table_touch_decision(
        table, &invalid_key, &destination, 8600u, 500u, &snapshot),
        "invalid key touch");
    CHECK(!connection_table_upsert_decision(
        NULL, &key, &destination, 8600u, 338u, TRUE,
        CONNECTION_DECISION_DIRECT, 500u), "NULL table upsert");
    CHECK(!connection_table_upsert_decision(
        table, NULL, &destination, 8600u, 338u, TRUE,
        CONNECTION_DECISION_DIRECT, 500u), "NULL key upsert");
    CHECK(!connection_table_upsert_decision(
        table, &key, NULL, 8600u, 338u, TRUE,
        CONNECTION_DECISION_DIRECT, 500u), "NULL destination upsert");
    CHECK(!connection_table_clear_decision_if_match(
        NULL, &key, &destination, 8600u,
        CONNECTION_DECISION_BLOCK, 500u), "NULL table clear");
    CHECK(!connection_table_clear_decision_if_match(
        table, NULL, &destination, 8600u,
        CONNECTION_DECISION_BLOCK, 500u), "NULL key clear");
    CHECK(!connection_table_clear_decision_if_match(
        table, &key, NULL, 8600u,
        CONNECTION_DECISION_BLOCK, 500u), "NULL destination clear");
    CHECK(!connection_table_clear_decision_if_match(
        table, &key, &destination, 8600u,
        CONNECTION_DECISION_NONE, 500u), "NONE expected clear");
    CHECK(!connection_table_clear_decision_if_match(
        table, &key, &destination, 8600u,
        (CONNECTION_DECISION)4, 500u), "invalid expected clear");

    CHECK(connection_table_get_full(table, &key, 0u, &snapshot),
          "snapshot after misses");
    CHECK(snapshot_equal_decision(
        &snapshot, AF_INET, IPV4_C, 8600u, 338u,
        CONNECTION_DECISION_BLOCK), "miss or invalid input mutated value");
    CHECK(connection_table_is_tracked(table, &key),
          "miss or invalid input mutated tracked state");
    CHECK(connection_table_cleanup(table, 151u, 50u) == 1u,
          "miss or invalid input mutated activity");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_clear_decision_preserves_value_and_tracked(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY key;
    CONNECTION_ADDRESS destination;
    CONNECTION_SNAPSHOT snapshot;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&key, IPPROTO_TCP, AF_INET, IPV4_A, 62006u), "key");
    CHECK(make_address(&destination, AF_INET, IPV4_C), "destination");
    CHECK(connection_table_upsert_decision(
        table, &key, &destination, 8700u, 339u, TRUE,
        CONNECTION_DECISION_PROXY, 100u), "insert");
    CHECK(connection_table_clear_decision_if_match(
        table, &key, &destination, 8700u,
        CONNECTION_DECISION_PROXY, 200u), "matching clear");
    CHECK(connection_table_get_full(table, &key, 0u, &snapshot),
          "snapshot after clear");
    CHECK(snapshot_equal_decision(
        &snapshot, AF_INET, IPV4_C, 8700u, 339u,
        CONNECTION_DECISION_NONE), "clear changed routing value");
    CHECK(connection_table_is_tracked(table, &key),
          "clear changed tracked state");
    CHECK(connection_table_touch_tracked(table, &key, 0u),
          "tracked behavior lost after clear");
    CHECK(!connection_table_touch_decision(
        table, &key, &destination, 8700u, 500u, &snapshot),
        "cleared decision remained touchable");
    CHECK(connection_table_cleanup(table, 220u, 20u) == 0u,
          "clear activity equality boundary removed entry");
    CHECK(connection_table_cleanup(table, 221u, 20u) == 1u,
          "clear activity was not 200");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_clear_mismatch_then_fresh_overwrite(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY key;
    CONNECTION_ADDRESS destination_a;
    CONNECTION_ADDRESS destination_b;
    CONNECTION_SNAPSHOT snapshot;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&key, IPPROTO_TCP, AF_INET, IPV4_A, 62007u), "key");
    CHECK(make_address(&destination_a, AF_INET, IPV4_C), "destination A");
    CHECK(make_address(&destination_b, AF_INET, IPV4_D), "destination B");
    CHECK(connection_table_upsert_decision(
        table, &key, &destination_a, 8800u, 340u, FALSE,
        CONNECTION_DECISION_DIRECT, 100u), "insert");

    CHECK(!connection_table_clear_decision_if_match(
        table, &key, &destination_b, 8800u,
        CONNECTION_DECISION_DIRECT, 500u), "wrong destination cleared decision");
    CHECK(!connection_table_clear_decision_if_match(
        table, &key, &destination_a, 8800u,
        CONNECTION_DECISION_BLOCK, 500u), "wrong decision cleared entry");
    CHECK(connection_table_get_full(table, &key, 0u, &snapshot),
          "snapshot after mismatches");
    CHECK(snapshot_equal_decision(
        &snapshot, AF_INET, IPV4_C, 8800u, 340u,
        CONNECTION_DECISION_DIRECT), "clear mismatch mutated value");
    CHECK(connection_table_cleanup(table, 151u, 50u) == 1u,
          "clear mismatch mutated activity");

    CHECK(connection_table_upsert_decision(
        table, &key, &destination_a, 8800u, 340u, FALSE,
        CONNECTION_DECISION_DIRECT, 200u), "reinsert");
    CHECK(connection_table_clear_decision_if_match(
        table, &key, &destination_a, 8800u,
        CONNECTION_DECISION_DIRECT, 250u), "clear before fresh overwrite");
    CHECK(connection_table_upsert_decision(
        table, &key, &destination_b, 8801u, 341u, TRUE,
        CONNECTION_DECISION_PROXY, 300u), "fresh-style overwrite");
    CHECK(connection_table_count(table) == 1u,
          "fresh-style overwrite created a node");
    CHECK(connection_table_get_full(table, &key, 0u, &snapshot),
          "fresh-style snapshot");
    CHECK(snapshot_equal_decision(
        &snapshot, AF_INET, IPV4_D, 8801u, 341u,
        CONNECTION_DECISION_PROXY), "fresh-style value mismatch");
    CHECK(connection_table_is_tracked(table, &key),
          "fresh-style tracked value mismatch");
    connection_table_destroy(table);
    return TRUE;
}

static BOOL test_udp_tracked_reverse_ignores_decision(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY legacy_key;
    CONNECTION_KEY decision_key;
    CONNECTION_KEY found;
    CONNECTION_ADDRESS destination;
    CONNECTION_SNAPSHOT snapshot;

    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&legacy_key, IPPROTO_UDP, AF_INET, IPV4_A, 62008u),
          "legacy UDP key");
    CHECK(make_key(&decision_key, IPPROTO_UDP, AF_INET, IPV4_B, 62009u),
          "decision UDP key");
    CHECK(make_address(&destination, AF_INET, IPV4_C), "destination");
    CHECK(connection_table_upsert(
        table, &legacy_key, &destination, 8900u, 342u, TRUE, 200u),
        "legacy UDP insert");
    CHECK(connection_table_find_udp_sender(
        table, AF_INET, 342u, &destination, 8900u, &found),
        "legacy NONE reverse lookup");
    CHECK(key_equal(&found, &legacy_key),
          "legacy NONE entry not returned");
    CHECK(connection_table_touch_tracked(table, &legacy_key, 210u),
          "legacy NONE tracked touch failed");
    CHECK(connection_table_get_full(table, &legacy_key, 0u, &snapshot),
          "legacy NONE snapshot");
    CHECK(snapshot.decision == CONNECTION_DECISION_NONE,
          "legacy UDP decision changed");

    CHECK(connection_table_upsert_decision(
        table, &decision_key, &destination, 8900u, 342u, TRUE,
        CONNECTION_DECISION_BLOCK, 100u), "decision UDP insert");
    CHECK(connection_table_touch_tracked(table, &decision_key, 250u),
          "decision-bearing UDP tracked touch failed");
    CHECK(connection_table_find_udp_sender(
        table, AF_INET, 342u, &destination, 8900u, &found),
        "decision-bearing reverse lookup");
    CHECK(key_equal(&found, &decision_key),
          "reverse lookup used decision as a filter");
    connection_table_destroy(table);
    return TRUE;
}

typedef struct DECISION_TOUCH_CONTEXT {
    CONNECTION_TABLE *table;
    const CONNECTION_KEY *key;
    const CONNECTION_ADDRESS *destination;
    ULONGLONG timestamp;
    HANDLE start_event;
    volatile LONG failed;
} DECISION_TOUCH_CONTEXT;

static DWORD WINAPI touch_decision_thread(LPVOID parameter)
{
    DECISION_TOUCH_CONTEXT *context =
        (DECISION_TOUCH_CONTEXT *)parameter;
    CONNECTION_SNAPSHOT snapshot;

    if (WaitForSingleObject(context->start_event, INFINITE) != WAIT_OBJECT_0 ||
        !connection_table_touch_decision(
            context->table,
            context->key,
            context->destination,
            9000u,
            context->timestamp,
            &snapshot) ||
        !snapshot_equal_decision(
            &snapshot,
            AF_INET,
            IPV4_D,
            9000u,
            343u,
            CONNECTION_DECISION_DIRECT)) {
        InterlockedExchange(&context->failed, 1);
    }

    return 0u;
}

static BOOL test_touch_decision_concurrent_cas_max(void)
{
    static const ULONGLONG timestamps[] = {
        500u, 150u, 450u, 0u, 350u, 499u, 200u, 300u
    };
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY key;
    CONNECTION_ADDRESS destination;
    CONNECTION_SNAPSHOT snapshot;
    DECISION_TOUCH_CONTEXT contexts[ARRAY_COUNT(timestamps)];
    HANDLE threads[ARRAY_COUNT(timestamps)];
    HANDLE start_event;
    SIZE_T index;

    memset(contexts, 0, sizeof(contexts));
    memset(threads, 0, sizeof(threads));
    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&key, IPPROTO_TCP, AF_INET, IPV4_A, 62010u), "key");
    CHECK(make_address(&destination, AF_INET, IPV4_D), "destination");
    CHECK(connection_table_upsert_decision(
        table, &key, &destination, 9000u, 343u, FALSE,
        CONNECTION_DECISION_DIRECT, 100u), "insert");
    start_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    CHECK(start_event != NULL, "start event creation failed");

    for (index = 0u; index < ARRAY_COUNT(timestamps); ++index) {
        contexts[index].table = table;
        contexts[index].key = &key;
        contexts[index].destination = &destination;
        contexts[index].timestamp = timestamps[index];
        contexts[index].start_event = start_event;
        threads[index] = CreateThread(
            NULL, 0u, touch_decision_thread, &contexts[index], 0u, NULL);
        CHECK(threads[index] != NULL, "decision touch thread creation failed");
    }

    CHECK(SetEvent(start_event), "concurrent start failed");
    CHECK(WaitForMultipleObjects(
        (DWORD)ARRAY_COUNT(threads), threads, TRUE, INFINITE) == WAIT_OBJECT_0,
        "decision touch threads did not exit");
    for (index = 0u; index < ARRAY_COUNT(timestamps); ++index) {
        CHECK(InterlockedCompareExchange(
            &contexts[index].failed, 0, 0) == 0,
            "a concurrent decision touch failed");
        CloseHandle(threads[index]);
    }
    CloseHandle(start_event);

    CHECK(connection_table_get_full(table, &key, 0u, &snapshot),
          "snapshot after concurrent touch");
    CHECK(snapshot_equal_decision(
        &snapshot, AF_INET, IPV4_D, 9000u, 343u,
        CONNECTION_DECISION_DIRECT), "concurrent touch corrupted value");
    CHECK(connection_table_cleanup(table, 520u, 20u) == 0u,
          "concurrent maximum equality boundary removed entry");
    CHECK(connection_table_cleanup(table, 521u, 20u) == 1u,
          "concurrent decision maximum did not reach 500");
    connection_table_destroy(table);
    return TRUE;
}

typedef struct DECISION_CLEAR_RACE_CONTEXT {
    CONNECTION_TABLE *table;
    const CONNECTION_KEY *key;
    const CONNECTION_ADDRESS *destination;
    HANDLE start_event;
    volatile LONG failed;
} DECISION_CLEAR_RACE_CONTEXT;

static DWORD WINAPI decision_race_touch_thread(LPVOID parameter)
{
    DECISION_CLEAR_RACE_CONTEXT *context =
        (DECISION_CLEAR_RACE_CONTEXT *)parameter;
    CONNECTION_SNAPSHOT snapshot;
    BOOL touched;

    if (WaitForSingleObject(context->start_event, INFINITE) != WAIT_OBJECT_0) {
        InterlockedExchange(&context->failed, 1);
        return 0u;
    }

    touched = connection_table_touch_decision(
        context->table,
        context->key,
        context->destination,
        9100u,
        400u,
        &snapshot);
    if (touched && !snapshot_equal_decision(
            &snapshot,
            AF_INET,
            IPV4_C,
            9100u,
            344u,
            CONNECTION_DECISION_DIRECT)) {
        InterlockedExchange(&context->failed, 1);
    }

    return 0u;
}

static DWORD WINAPI decision_race_clear_thread(LPVOID parameter)
{
    DECISION_CLEAR_RACE_CONTEXT *context =
        (DECISION_CLEAR_RACE_CONTEXT *)parameter;

    if (WaitForSingleObject(context->start_event, INFINITE) != WAIT_OBJECT_0 ||
        !connection_table_clear_decision_if_match(
            context->table,
            context->key,
            context->destination,
            9100u,
            CONNECTION_DECISION_DIRECT,
            500u)) {
        InterlockedExchange(&context->failed, 1);
    }

    return 0u;
}

static BOOL test_concurrent_touch_conditional_clear_consistency(void)
{
    CONNECTION_TABLE *table = connection_table_create();
    CONNECTION_KEY key;
    CONNECTION_ADDRESS destination;
    CONNECTION_SNAPSHOT snapshot;
    DECISION_CLEAR_RACE_CONTEXT context;
    HANDLE threads[2];

    memset(&context, 0, sizeof(context));
    memset(threads, 0, sizeof(threads));
    CHECK(table != NULL, "table allocation failed");
    CHECK(make_key(&key, IPPROTO_TCP, AF_INET, IPV4_A, 62011u), "key");
    CHECK(make_address(&destination, AF_INET, IPV4_C), "destination");
    CHECK(connection_table_upsert_decision(
        table, &key, &destination, 9100u, 344u, TRUE,
        CONNECTION_DECISION_DIRECT, 100u), "insert");

    context.table = table;
    context.key = &key;
    context.destination = &destination;
    context.start_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    CHECK(context.start_event != NULL, "race event creation failed");
    threads[0] = CreateThread(
        NULL, 0u, decision_race_touch_thread, &context, 0u, NULL);
    CHECK(threads[0] != NULL, "race touch thread creation failed");
    threads[1] = CreateThread(
        NULL, 0u, decision_race_clear_thread, &context, 0u, NULL);
    CHECK(threads[1] != NULL, "race clear thread creation failed");
    CHECK(SetEvent(context.start_event), "race start failed");
    CHECK(WaitForMultipleObjects(2u, threads, TRUE, INFINITE) == WAIT_OBJECT_0,
          "race threads did not exit");
    CloseHandle(threads[1]);
    CloseHandle(threads[0]);
    CloseHandle(context.start_event);

    CHECK(InterlockedCompareExchange(&context.failed, 0, 0) == 0,
          "touch/clear race operation failed");
    CHECK(connection_table_get_full(table, &key, 0u, &snapshot),
          "snapshot after touch/clear race");
    CHECK(snapshot_equal_decision(
        &snapshot, AF_INET, IPV4_C, 9100u, 344u,
        CONNECTION_DECISION_NONE), "touch/clear race corrupted value");
    CHECK(connection_table_is_tracked(table, &key),
          "touch/clear race changed tracked state");
    CHECK(connection_table_count(table) == 1u,
          "touch/clear race changed entry count");
    CHECK(connection_table_cleanup(table, 520u, 20u) == 0u,
          "clear timestamp equality boundary removed entry");
    CHECK(connection_table_cleanup(table, 521u, 20u) == 1u,
          "touch/clear final activity was not 500");
    connection_table_destroy(table);
    return TRUE;
}

typedef BOOL (*TEST_FUNCTION)(void);

typedef struct TEST_CASE {
    const char *name;
    TEST_FUNCTION function;
} TEST_CASE;

int main(int argc, char **argv)
{
    static const TEST_CASE tests[] = {
        {"protocol_collision", test_protocol_collision},
        {"reverse_insertion_order", test_reverse_insertion_order},
        {"different_ports_control", test_different_ports_control},
        {"ipv4_ipv6_separation", test_ipv4_ipv6_separation},
        {"different_local_ipv4", test_different_local_ipv4},
        {"different_local_ipv6", test_different_local_ipv6},
        {"exact_update", test_exact_update},
        {"one_field_difference", test_one_field_difference},
        {"remove_tcp_preserves_udp", test_remove_tcp_preserves_udp},
        {"remove_family_address_preserves_other",
         test_remove_family_address_preserves_other},
        {"cleanup_stale_fresh_same_bucket",
         test_cleanup_stale_fresh_same_bucket},
        {"deliberate_hash_collision", test_deliberate_hash_collision},
        {"clear_and_reuse", test_clear_and_reuse},
        {"consistent_snapshot", test_consistent_snapshot},
        {"reverse_udp_filtering", test_reverse_udp_filtering},
        {"reverse_udp_newest", test_reverse_udp_newest},
        {"get_full_timestamp_regression",
         test_get_full_timestamp_regression},
        {"upsert_timestamp_regression",
         test_upsert_timestamp_regression},
        {"concurrent_monotonic_touch",
         test_concurrent_monotonic_touch},
        {"equal_timestamp", test_equal_timestamp},
        {"invalid_protocol_family", test_invalid_protocol_family},
        {"null_invalid_arguments", test_null_invalid_arguments},
        {"cleanup_bucket_chain", test_cleanup_bucket_chain},
        {"repeated_lifecycle", test_repeated_lifecycle},
        {"touch_tracked_updates_activity",
         test_touch_tracked_updates_activity},
        {"touch_tracked_monotonic_older_and_equal",
         test_touch_tracked_monotonic_older_and_equal},
        {"touch_tracked_rejects_untracked_without_mutation",
         test_touch_tracked_rejects_untracked_without_mutation},
        {"touch_tracked_exact_key_isolation",
         test_touch_tracked_exact_key_isolation},
        {"touch_tracked_invalid_inputs",
         test_touch_tracked_invalid_inputs},
        {"touch_tracked_concurrent_cas_max",
         test_touch_tracked_concurrent_cas_max},
        {"decision_round_trip_and_overwrite",
         test_decision_round_trip_and_overwrite},
        {"invalid_decision_rejected_without_mutation",
         test_invalid_decision_rejected_without_mutation},
        {"legacy_upsert_decision_none_tracked",
         test_legacy_upsert_decision_none_tracked},
        {"decision_exact_key_separation",
         test_decision_exact_key_separation},
        {"touch_decision_full_snapshot_monotonic",
         test_touch_decision_full_snapshot_monotonic},
        {"touch_decision_mismatch_and_invalid_inputs",
         test_touch_decision_mismatch_and_invalid_inputs},
        {"clear_decision_preserves_value_and_tracked",
         test_clear_decision_preserves_value_and_tracked},
        {"clear_mismatch_then_fresh_overwrite",
         test_clear_mismatch_then_fresh_overwrite},
        {"udp_tracked_reverse_ignores_decision",
         test_udp_tracked_reverse_ignores_decision},
        {"touch_decision_concurrent_cas_max",
         test_touch_decision_concurrent_cas_max},
        {"concurrent_touch_conditional_clear_consistency",
         test_concurrent_touch_conditional_clear_consistency}
    };
    BOOL quiet = argc == 2 && strcmp(argv[1], "--quiet") == 0;
    SIZE_T passed = 0u;
    SIZE_T index;

    if (argc > 2 || (argc == 2 && !quiet)) {
        fprintf(stderr, "usage: connection_table_tests.exe [--quiet]\n");
        return 2;
    }

    for (index = 0u; index < ARRAY_COUNT(tests); ++index) {
        if (tests[index].function()) {
            ++passed;
            if (!quiet) {
                printf("PASS %s\n", tests[index].name);
            }
        } else {
            fprintf(
                stderr,
                "SUMMARY: %llu passed, %llu failed\n",
                (unsigned long long)passed,
                (unsigned long long)(ARRAY_COUNT(tests) - passed));
            return 1;
        }
    }

    printf(
        "SUMMARY: %llu passed, 0 failed\n",
        (unsigned long long)passed);
    return 0;
}
