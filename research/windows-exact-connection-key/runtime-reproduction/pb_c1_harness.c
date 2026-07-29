#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEXT_IP_SIZE 16
#define PATH_BUFFER_SIZE 32768
#define MARKER_BUFFER_SIZE 256
#define DETAIL_BUFFER_SIZE 256
#define UDP_BUFFER_SIZE 2048

typedef struct HARNESS_CONFIG {
    char udp_local_ip[TEXT_IP_SIZE];
    UINT16 udp_local_port;
    char tcp_local_ip[TEXT_IP_SIZE];
    UINT16 tcp_local_port;
    char udp_destination_ip[TEXT_IP_SIZE];
    UINT16 udp_destination_port;
    char tcp_destination_ip[TEXT_IP_SIZE];
    UINT16 tcp_destination_port;
    DWORD seed_delay_ms;
    DWORD udp_timeout_ms;
    DWORD tcp_timeout_ms;
    DWORD hold_ms;
    char jsonl_log[PATH_BUFFER_SIZE];
} HARNESS_CONFIG;

typedef struct ARGUMENT_STATE {
    BOOL udp_local_ip;
    BOOL udp_local_port;
    BOOL tcp_local_ip;
    BOOL tcp_local_port;
    BOOL udp_destination_ip;
    BOOL udp_destination_port;
    BOOL tcp_destination_ip;
    BOOL tcp_destination_port;
    BOOL seed_delay_ms;
    BOOL udp_timeout_ms;
    BOOL tcp_timeout_ms;
    BOOL hold_ms;
    BOOL jsonl_log;
} ARGUMENT_STATE;

typedef struct EVENT_CONTEXT {
    FILE *file;
    char run_id[128];
    DWORD pid;
} EVENT_CONTEXT;

typedef struct CONNECT_RESULT {
    BOOL connected;
    int return_code;
    int wsa_error;
    char detail[DETAIL_BUFFER_SIZE];
} CONNECT_RESULT;

static void print_usage(const char *program)
{
    fprintf(stderr,
        "Usage: %s [--udp-local-ip IPv4] --udp-local-port PORT "
        "[--tcp-local-ip IPv4] --tcp-local-port PORT "
        "--udp-destination-ip IPv4 --udp-destination-port PORT "
        "--tcp-destination-ip IPv4 --tcp-destination-port PORT "
        "--seed-delay-ms MS --udp-timeout-ms MS --tcp-timeout-ms MS "
        "--hold-ms MS --jsonl-log PATH\n",
        program);
}

static BOOL copy_argument(char *destination, size_t destination_size, const char *value)
{
    size_t length;
    if (destination == NULL || destination_size == 0 || value == NULL)
        return FALSE;
    length = strlen(value);
    if (length == 0 || length >= destination_size)
        return FALSE;
    memcpy(destination, value, length + 1);
    return TRUE;
}

static BOOL parse_port(const char *text, UINT16 *port)
{
    char *end = NULL;
    const char *cursor;
    unsigned long value;

    if (text == NULL || text[0] == '\0' || port == NULL)
        return FALSE;
    for (cursor = text; *cursor != '\0'; cursor++)
    {
        if (*cursor < '0' || *cursor > '9')
            return FALSE;
    }
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < 1 || value > 65535)
        return FALSE;
    *port = (UINT16)value;
    return TRUE;
}

static BOOL parse_duration(const char *text, DWORD *duration)
{
    char *end = NULL;
    const char *cursor;
    unsigned long long value;

    if (text == NULL || text[0] == '\0' || duration == NULL)
        return FALSE;
    for (cursor = text; *cursor != '\0'; cursor++)
    {
        if (*cursor < '0' || *cursor > '9')
            return FALSE;
    }
    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value > INT_MAX)
        return FALSE;
    *duration = (DWORD)value;
    return TRUE;
}

static BOOL consume_unique(BOOL *seen, const char *name)
{
    if (*seen)
    {
        fprintf(stderr, "Duplicate argument: %s\n", name);
        return FALSE;
    }
    *seen = TRUE;
    return TRUE;
}

static BOOL parse_arguments(int argc, char **argv, HARNESS_CONFIG *config)
{
    ARGUMENT_STATE seen;
    int index;

    memset(config, 0, sizeof(*config));
    memset(&seen, 0, sizeof(seen));
    strcpy(config->udp_local_ip, "0.0.0.0");
    strcpy(config->tcp_local_ip, "0.0.0.0");

    for (index = 1; index < argc; index++)
    {
        const char *name = argv[index];
        const char *value;

        if (index + 1 >= argc)
        {
            fprintf(stderr, "Missing value for argument: %s\n", name);
            return FALSE;
        }
        value = argv[++index];

        if (strcmp(name, "--udp-local-ip") == 0)
        {
            if (!consume_unique(&seen.udp_local_ip, name) ||
                !copy_argument(config->udp_local_ip, sizeof(config->udp_local_ip), value))
                return FALSE;
        }
        else if (strcmp(name, "--udp-local-port") == 0)
        {
            if (!consume_unique(&seen.udp_local_port, name) ||
                !parse_port(value, &config->udp_local_port))
                return FALSE;
        }
        else if (strcmp(name, "--tcp-local-ip") == 0)
        {
            if (!consume_unique(&seen.tcp_local_ip, name) ||
                !copy_argument(config->tcp_local_ip, sizeof(config->tcp_local_ip), value))
                return FALSE;
        }
        else if (strcmp(name, "--tcp-local-port") == 0)
        {
            if (!consume_unique(&seen.tcp_local_port, name) ||
                !parse_port(value, &config->tcp_local_port))
                return FALSE;
        }
        else if (strcmp(name, "--udp-destination-ip") == 0)
        {
            if (!consume_unique(&seen.udp_destination_ip, name) ||
                !copy_argument(config->udp_destination_ip, sizeof(config->udp_destination_ip), value))
                return FALSE;
        }
        else if (strcmp(name, "--udp-destination-port") == 0)
        {
            if (!consume_unique(&seen.udp_destination_port, name) ||
                !parse_port(value, &config->udp_destination_port))
                return FALSE;
        }
        else if (strcmp(name, "--tcp-destination-ip") == 0)
        {
            if (!consume_unique(&seen.tcp_destination_ip, name) ||
                !copy_argument(config->tcp_destination_ip, sizeof(config->tcp_destination_ip), value))
                return FALSE;
        }
        else if (strcmp(name, "--tcp-destination-port") == 0)
        {
            if (!consume_unique(&seen.tcp_destination_port, name) ||
                !parse_port(value, &config->tcp_destination_port))
                return FALSE;
        }
        else if (strcmp(name, "--seed-delay-ms") == 0)
        {
            if (!consume_unique(&seen.seed_delay_ms, name) ||
                !parse_duration(value, &config->seed_delay_ms))
                return FALSE;
        }
        else if (strcmp(name, "--udp-timeout-ms") == 0)
        {
            if (!consume_unique(&seen.udp_timeout_ms, name) ||
                !parse_duration(value, &config->udp_timeout_ms))
                return FALSE;
        }
        else if (strcmp(name, "--tcp-timeout-ms") == 0)
        {
            if (!consume_unique(&seen.tcp_timeout_ms, name) ||
                !parse_duration(value, &config->tcp_timeout_ms))
                return FALSE;
        }
        else if (strcmp(name, "--hold-ms") == 0)
        {
            if (!consume_unique(&seen.hold_ms, name) ||
                !parse_duration(value, &config->hold_ms))
                return FALSE;
        }
        else if (strcmp(name, "--jsonl-log") == 0)
        {
            if (!consume_unique(&seen.jsonl_log, name) ||
                !copy_argument(config->jsonl_log, sizeof(config->jsonl_log), value))
                return FALSE;
        }
        else
        {
            fprintf(stderr, "Unknown argument: %s\n", name);
            return FALSE;
        }
    }

    if (!seen.udp_local_port || !seen.tcp_local_port ||
        !seen.udp_destination_ip || !seen.udp_destination_port ||
        !seen.tcp_destination_ip || !seen.tcp_destination_port ||
        !seen.seed_delay_ms || !seen.udp_timeout_ms ||
        !seen.tcp_timeout_ms || !seen.hold_ms || !seen.jsonl_log)
    {
        fprintf(stderr, "One or more required arguments are missing.\n");
        return FALSE;
    }

    return TRUE;
}

static BOOL validate_ipv4(const char *text, struct in_addr *address)
{
    return InetPtonA(AF_INET, text, address) == 1;
}

static BOOL write_json_string(FILE *file, const char *text)
{
    const unsigned char *cursor = (const unsigned char *)(text != NULL ? text : "");

    if (fputc('"', file) == EOF)
        return FALSE;
    while (*cursor != '\0')
    {
        int result;
        switch (*cursor)
        {
            case '"':  result = fputs("\\\"", file); break;
            case '\\': result = fputs("\\\\", file); break;
            case '\b': result = fputs("\\b", file); break;
            case '\f': result = fputs("\\f", file); break;
            case '\n': result = fputs("\\n", file); break;
            case '\r': result = fputs("\\r", file); break;
            case '\t': result = fputs("\\t", file); break;
            default:
                if (*cursor < 0x20)
                    result = fprintf(file, "\\u%04x", (unsigned int)*cursor);
                else
                    result = fputc(*cursor, file);
                break;
        }
        if (result == EOF || result < 0)
            return FALSE;
        cursor++;
    }
    return fputc('"', file) != EOF;
}

static BOOL write_json_name_and_string(FILE *file, const char *name, const char *value)
{
    if (write_json_string(file, name) == FALSE || fputc(':', file) == EOF)
        return FALSE;
    return write_json_string(file, value);
}

static BOOL log_event(
    EVENT_CONTEXT *context,
    const char *phase,
    const char *protocol,
    const char *operation,
    const char *requested_local_ip,
    UINT16 requested_local_port,
    const char *actual_local_ip,
    UINT16 actual_local_port,
    const char *intended_remote_ip,
    UINT16 intended_remote_port,
    long long return_code,
    int wsa_error,
    const char *marker,
    const char *detail,
    int success)
{
    SYSTEMTIME timestamp;
    ULONGLONG monotonic_ms;
    FILE *file;

    if (context == NULL || context->file == NULL)
        return FALSE;
    file = context->file;
    GetSystemTime(&timestamp);
    monotonic_ms = GetTickCount64();

    if (fputc('{', file) == EOF ||
        !write_json_name_and_string(file, "run_id", context->run_id) ||
        fputc(',', file) == EOF)
        return FALSE;

    if (fputs("\"timestamp\":", file) < 0 ||
        fprintf(file, "\"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ\",",
            (unsigned int)timestamp.wYear,
            (unsigned int)timestamp.wMonth,
            (unsigned int)timestamp.wDay,
            (unsigned int)timestamp.wHour,
            (unsigned int)timestamp.wMinute,
            (unsigned int)timestamp.wSecond,
            (unsigned int)timestamp.wMilliseconds) < 0 ||
        fprintf(file, "\"monotonic_ms\":%llu,\"pid\":%lu,",
            (unsigned long long)monotonic_ms,
            (unsigned long)context->pid) < 0)
        return FALSE;

    if (!write_json_name_and_string(file, "phase", phase) ||
        fputc(',', file) == EOF ||
        !write_json_name_and_string(file, "protocol", protocol) ||
        fputc(',', file) == EOF ||
        !write_json_name_and_string(file, "operation", operation) ||
        fputc(',', file) == EOF ||
        !write_json_name_and_string(file, "requested_local_ip", requested_local_ip) ||
        fprintf(file, ",\"requested_local_port\":%u,", (unsigned int)requested_local_port) < 0 ||
        !write_json_name_and_string(file, "actual_local_ip", actual_local_ip) ||
        fprintf(file, ",\"actual_local_port\":%u,", (unsigned int)actual_local_port) < 0 ||
        !write_json_name_and_string(file, "intended_remote_ip", intended_remote_ip) ||
        fprintf(file, ",\"intended_remote_port\":%u,", (unsigned int)intended_remote_port) < 0 ||
        fprintf(file, "\"return_code\":%lld,\"wsa_error\":%d,",
            return_code, wsa_error) < 0 ||
        !write_json_name_and_string(file, "marker", marker) ||
        fputc(',', file) == EOF ||
        !write_json_name_and_string(file, "detail", detail) ||
        fprintf(file, ",\"success\":%d}\n", success) < 0)
        return FALSE;

    return fflush(file) == 0;
}

static void make_run_id(EVENT_CONTEXT *context)
{
    SYSTEMTIME timestamp;
    GetSystemTime(&timestamp);
    snprintf(context->run_id, sizeof(context->run_id),
        "C1-%04u%02u%02uT%02u%02u%02u%03uZ-P%lu-T%llu",
        (unsigned int)timestamp.wYear,
        (unsigned int)timestamp.wMonth,
        (unsigned int)timestamp.wDay,
        (unsigned int)timestamp.wHour,
        (unsigned int)timestamp.wMinute,
        (unsigned int)timestamp.wSecond,
        (unsigned int)timestamp.wMilliseconds,
        (unsigned long)context->pid,
        (unsigned long long)GetTickCount64());
}

static BOOL inspect_local_endpoint(
    SOCKET socket_handle,
    const struct in_addr *requested_address,
    UINT16 requested_port,
    char actual_ip[TEXT_IP_SIZE],
    UINT16 *actual_port,
    int *return_code,
    int *wsa_error)
{
    struct sockaddr_in local_address;
    int local_address_length = (int)sizeof(local_address);
    int result;

    memset(&local_address, 0, sizeof(local_address));
    result = getsockname(
        socket_handle,
        (struct sockaddr *)&local_address,
        &local_address_length);
    *return_code = result;
    if (result == SOCKET_ERROR)
    {
        *wsa_error = WSAGetLastError();
        return FALSE;
    }
    *wsa_error = 0;

    if (local_address.sin_family != AF_INET ||
        InetNtopA(AF_INET, &local_address.sin_addr, actual_ip, TEXT_IP_SIZE) == NULL)
    {
        *wsa_error = WSAGetLastError();
        *return_code = SOCKET_ERROR;
        return FALSE;
    }
    *actual_port = ntohs(local_address.sin_port);
    return local_address.sin_addr.s_addr == requested_address->s_addr &&
        *actual_port == requested_port;
}

static CONNECT_RESULT connect_with_timeout(
    SOCKET socket_handle,
    const struct sockaddr_in *remote_address,
    DWORD timeout_ms)
{
    CONNECT_RESULT result;
    u_long nonblocking = 1;
    int connect_result;

    memset(&result, 0, sizeof(result));
    result.return_code = SOCKET_ERROR;
    strcpy(result.detail, "TCP connect failed");

    if (ioctlsocket(socket_handle, FIONBIO, &nonblocking) == SOCKET_ERROR)
    {
        result.wsa_error = WSAGetLastError();
        strcpy(result.detail, "ioctlsocket(FIONBIO=1) failed");
        return result;
    }

    connect_result = connect(
        socket_handle,
        (const struct sockaddr *)remote_address,
        (int)sizeof(*remote_address));
    if (connect_result == SOCKET_ERROR)
    {
        int connect_error = WSAGetLastError();
        if (connect_error == WSAEWOULDBLOCK ||
            connect_error == WSAEINPROGRESS ||
            connect_error == WSAEALREADY)
        {
            fd_set write_set;
            fd_set error_set;
            struct timeval timeout;
            int select_result;

            FD_ZERO(&write_set);
            FD_ZERO(&error_set);
            FD_SET(socket_handle, &write_set);
            FD_SET(socket_handle, &error_set);
            timeout.tv_sec = (long)(timeout_ms / 1000);
            timeout.tv_usec = (long)((timeout_ms % 1000) * 1000);

            select_result = select(0, NULL, &write_set, &error_set, &timeout);
            if (select_result == SOCKET_ERROR)
            {
                result.wsa_error = WSAGetLastError();
                strcpy(result.detail, "select() failed during TCP connect");
                return result;
            }
            if (select_result == 0)
            {
                result.wsa_error = WSAETIMEDOUT;
                strcpy(result.detail, "TCP connect timeout");
                return result;
            }

            {
                int socket_error = 0;
                int socket_error_length = (int)sizeof(socket_error);
                int getsockopt_result = getsockopt(
                    socket_handle,
                    SOL_SOCKET,
                    SO_ERROR,
                    (char *)&socket_error,
                    &socket_error_length);
                if (getsockopt_result == SOCKET_ERROR)
                {
                    result.wsa_error = WSAGetLastError();
                    strcpy(result.detail, "getsockopt(SO_ERROR) failed");
                    return result;
                }
                if (socket_error != 0)
                {
                    result.wsa_error = socket_error;
                    strcpy(result.detail, "TCP connect completed with socket error");
                    return result;
                }
            }
        }
        else
        {
            result.wsa_error = connect_error;
            strcpy(result.detail, "connect() failed immediately");
            return result;
        }
    }

    nonblocking = 0;
    if (ioctlsocket(socket_handle, FIONBIO, &nonblocking) == SOCKET_ERROR)
    {
        result.wsa_error = WSAGetLastError();
        strcpy(result.detail, "ioctlsocket(FIONBIO=0) failed");
        return result;
    }

    result.connected = TRUE;
    result.return_code = 0;
    result.wsa_error = 0;
    strcpy(result.detail, "TCP connect succeeded");
    return result;
}

static int send_all(SOCKET socket_handle, const char *buffer, int length, int *wsa_error)
{
    int total = 0;

    while (total < length)
    {
        int result = send(socket_handle, buffer + total, length - total, 0);
        if (result == SOCKET_ERROR)
        {
            *wsa_error = WSAGetLastError();
            return SOCKET_ERROR;
        }
        if (result == 0)
        {
            *wsa_error = WSAECONNRESET;
            return SOCKET_ERROR;
        }
        total += result;
    }
    *wsa_error = 0;
    return total;
}

int main(int argc, char **argv)
{
    HARNESS_CONFIG config;
    EVENT_CONTEXT event_context;
    WSADATA wsa_data;
    BOOL wsa_started = FALSE;
    SOCKET udp_socket = INVALID_SOCKET;
    SOCKET tcp_socket = INVALID_SOCKET;
    struct in_addr udp_local_address;
    struct in_addr tcp_local_address;
    struct in_addr udp_destination_address;
    struct in_addr tcp_destination_address;
    struct sockaddr_in socket_address;
    char udp_actual_ip[TEXT_IP_SIZE] = "";
    char tcp_actual_ip[TEXT_IP_SIZE] = "";
    UINT16 udp_actual_port = 0;
    UINT16 tcp_actual_port = 0;
    char udp_marker[MARKER_BUFFER_SIZE] = "";
    char tcp_marker[MARKER_BUFFER_SIZE] = "";
    BOOL udp_seed_confirmed = FALSE;
    BOOL run_success = FALSE;
    int exit_code = 1;
    int result;
    int wsa_error = 0;

    memset(&event_context, 0, sizeof(event_context));

    if (!parse_arguments(argc, argv, &config))
    {
        print_usage(argv[0]);
        return 2;
    }

    result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (result != 0)
    {
        fprintf(stderr, "WSAStartup failed: %d\n", result);
        return 3;
    }
    wsa_started = TRUE;

    if (!validate_ipv4(config.udp_local_ip, &udp_local_address) ||
        !validate_ipv4(config.tcp_local_ip, &tcp_local_address) ||
        !validate_ipv4(config.udp_destination_ip, &udp_destination_address) ||
        !validate_ipv4(config.tcp_destination_ip, &tcp_destination_address))
    {
        fprintf(stderr, "One or more IPv4 arguments are invalid.\n");
        exit_code = 4;
        goto cleanup;
    }

    event_context.file = fopen(config.jsonl_log, "ab");
    if (event_context.file == NULL)
    {
        fprintf(stderr, "Failed to open JSONL log '%s': errno=%d\n",
            config.jsonl_log, errno);
        exit_code = 5;
        goto cleanup;
    }
    event_context.pid = GetCurrentProcessId();
    make_run_id(&event_context);

#define LOG_OR_FAIL(phase_value, protocol_value, operation_value, \
                    requested_ip_value, requested_port_value, actual_ip_value, \
                    actual_port_value, remote_ip_value, remote_port_value, \
                    return_code_value, wsa_error_value, marker_value, detail_value) \
    do { \
        if (!log_event(&event_context, phase_value, protocol_value, operation_value, \
                requested_ip_value, requested_port_value, actual_ip_value, \
                actual_port_value, remote_ip_value, remote_port_value, \
                return_code_value, wsa_error_value, marker_value, detail_value, -1)) { \
            fprintf(stderr, "Failed to write JSONL phase %s.\n", phase_value); \
            exit_code = 6; \
            goto cleanup; \
        } \
    } while (0)

    LOG_OR_FAIL("START", "HARNESS", "start",
        "", 0, "", 0, "", 0, 0, 0, "", "C1 harness started");

    snprintf(udp_marker, sizeof(udp_marker), "PB_C1_UDP_%s", event_context.run_id);
    snprintf(tcp_marker, sizeof(tcp_marker), "PB_C1_TCP_%s", event_context.run_id);

    udp_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_socket == INVALID_SOCKET)
    {
        wsa_error = WSAGetLastError();
        LOG_OR_FAIL("UDP_SOCKET_CREATED", "UDP", "socket",
            config.udp_local_ip, config.udp_local_port, "", 0,
            config.udp_destination_ip, config.udp_destination_port,
            SOCKET_ERROR, wsa_error, udp_marker, "UDP socket creation failed");
        exit_code = 10;
        goto cleanup;
    }
    LOG_OR_FAIL("UDP_SOCKET_CREATED", "UDP", "socket",
        config.udp_local_ip, config.udp_local_port, "", 0,
        config.udp_destination_ip, config.udp_destination_port,
        0, 0, udp_marker, "UDP socket created");

    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sin_family = AF_INET;
    socket_address.sin_addr = udp_local_address;
    socket_address.sin_port = htons(config.udp_local_port);
    result = bind(udp_socket, (struct sockaddr *)&socket_address, sizeof(socket_address));
    if (result == SOCKET_ERROR)
    {
        wsa_error = WSAGetLastError();
        LOG_OR_FAIL("UDP_BIND_RESULT", "UDP", "bind",
            config.udp_local_ip, config.udp_local_port, "", 0,
            config.udp_destination_ip, config.udp_destination_port,
            result, wsa_error, udp_marker, "UDP bind failed");
        exit_code = 11;
        goto cleanup;
    }
    LOG_OR_FAIL("UDP_BIND_RESULT", "UDP", "bind",
        config.udp_local_ip, config.udp_local_port, "", 0,
        config.udp_destination_ip, config.udp_destination_port,
        result, 0, udp_marker, "UDP bind succeeded");

    {
        int getsockname_result = 0;
        int getsockname_error = 0;
        BOOL endpoint_matches = inspect_local_endpoint(
            udp_socket,
            &udp_local_address,
            config.udp_local_port,
            udp_actual_ip,
            &udp_actual_port,
            &getsockname_result,
            &getsockname_error);
        LOG_OR_FAIL("UDP_GETSOCKNAME", "UDP", "getsockname",
            config.udp_local_ip, config.udp_local_port,
            udp_actual_ip, udp_actual_port,
            config.udp_destination_ip, config.udp_destination_port,
            getsockname_result, getsockname_error, udp_marker,
            endpoint_matches ? "UDP local endpoint confirmed" : "UDP local endpoint mismatch or query failure");
        if (!endpoint_matches)
        {
            exit_code = 12;
            goto cleanup;
        }
    }

    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sin_family = AF_INET;
    socket_address.sin_addr = udp_destination_address;
    socket_address.sin_port = htons(config.udp_destination_port);
    result = sendto(
        udp_socket,
        udp_marker,
        (int)strlen(udp_marker),
        0,
        (struct sockaddr *)&socket_address,
        (int)sizeof(socket_address));
    if (result == SOCKET_ERROR)
    {
        wsa_error = WSAGetLastError();
        LOG_OR_FAIL("UDP_SEND_RESULT", "UDP", "sendto",
            config.udp_local_ip, config.udp_local_port,
            udp_actual_ip, udp_actual_port,
            config.udp_destination_ip, config.udp_destination_port,
            result, wsa_error, udp_marker, "UDP marker send failed");
        exit_code = 13;
        goto cleanup;
    }
    if (result != (int)strlen(udp_marker))
    {
        LOG_OR_FAIL("UDP_SEND_RESULT", "UDP", "sendto",
            config.udp_local_ip, config.udp_local_port,
            udp_actual_ip, udp_actual_port,
            config.udp_destination_ip, config.udp_destination_port,
            result, 0, udp_marker, "UDP marker send length mismatch");
        exit_code = 13;
        goto cleanup;
    }
    LOG_OR_FAIL("UDP_SEND_RESULT", "UDP", "sendto",
        config.udp_local_ip, config.udp_local_port,
        udp_actual_ip, udp_actual_port,
        config.udp_destination_ip, config.udp_destination_port,
        result, 0, udp_marker, "UDP marker sent");

    {
        fd_set read_set;
        struct timeval timeout;
        int select_result;
        char receive_buffer[UDP_BUFFER_SIZE];
        struct sockaddr_in receive_address;
        int receive_address_length = (int)sizeof(receive_address);
        int receive_result;

        FD_ZERO(&read_set);
        FD_SET(udp_socket, &read_set);
        timeout.tv_sec = (long)(config.udp_timeout_ms / 1000);
        timeout.tv_usec = (long)((config.udp_timeout_ms % 1000) * 1000);
        select_result = select(0, &read_set, NULL, NULL, &timeout);
        if (select_result == SOCKET_ERROR)
        {
            wsa_error = WSAGetLastError();
            LOG_OR_FAIL("UDP_RECV_RESULT", "UDP", "select",
                config.udp_local_ip, config.udp_local_port,
                udp_actual_ip, udp_actual_port,
                config.udp_destination_ip, config.udp_destination_port,
                select_result, wsa_error, udp_marker, "UDP echo select failed");
            exit_code = 14;
            goto cleanup;
        }
        if (select_result == 0)
        {
            LOG_OR_FAIL("UDP_RECV_RESULT", "UDP", "select",
                config.udp_local_ip, config.udp_local_port,
                udp_actual_ip, udp_actual_port,
                config.udp_destination_ip, config.udp_destination_port,
                0, WSAETIMEDOUT, udp_marker, "UDP echo timeout");
            exit_code = 15;
            goto cleanup;
        }

        memset(&receive_address, 0, sizeof(receive_address));
        receive_result = recvfrom(
            udp_socket,
            receive_buffer,
            (int)sizeof(receive_buffer),
            0,
            (struct sockaddr *)&receive_address,
            &receive_address_length);
        if (receive_result == SOCKET_ERROR)
        {
            wsa_error = WSAGetLastError();
            LOG_OR_FAIL("UDP_RECV_RESULT", "UDP", "recvfrom",
                config.udp_local_ip, config.udp_local_port,
                udp_actual_ip, udp_actual_port,
                config.udp_destination_ip, config.udp_destination_port,
                receive_result, wsa_error, udp_marker, "UDP echo receive failed");
            exit_code = 16;
            goto cleanup;
        }

        if (receive_result != (int)strlen(udp_marker) ||
            memcmp(receive_buffer, udp_marker, (size_t)receive_result) != 0)
        {
            LOG_OR_FAIL("UDP_RECV_RESULT", "UDP", "recvfrom",
                config.udp_local_ip, config.udp_local_port,
                udp_actual_ip, udp_actual_port,
                config.udp_destination_ip, config.udp_destination_port,
                receive_result, 0, udp_marker, "UDP echo payload mismatch");
            exit_code = 17;
            goto cleanup;
        }

        LOG_OR_FAIL("UDP_RECV_RESULT", "UDP", "recvfrom",
            config.udp_local_ip, config.udp_local_port,
            udp_actual_ip, udp_actual_port,
            config.udp_destination_ip, config.udp_destination_port,
            receive_result, 0, udp_marker, "UDP echo payload matched marker");
    }

    udp_seed_confirmed = TRUE;
    LOG_OR_FAIL("UDP_SEED_CONFIRMED", "UDP", "verify",
        config.udp_local_ip, config.udp_local_port,
        udp_actual_ip, udp_actual_port,
        config.udp_destination_ip, config.udp_destination_port,
        0, 0, udp_marker, "UDP seed confirmed");

    LOG_OR_FAIL("SEED_DELAY", "HARNESS", "Sleep",
        "", 0, "", 0, "", 0, 0, 0, "", "Seed delay begin");
    Sleep(config.seed_delay_ms);

    tcp_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (tcp_socket == INVALID_SOCKET)
    {
        wsa_error = WSAGetLastError();
        LOG_OR_FAIL("TCP_SOCKET_CREATED", "TCP", "socket",
            config.tcp_local_ip, config.tcp_local_port, "", 0,
            config.tcp_destination_ip, config.tcp_destination_port,
            SOCKET_ERROR, wsa_error, tcp_marker, "TCP socket creation failed");
        exit_code = 20;
        goto cleanup;
    }
    LOG_OR_FAIL("TCP_SOCKET_CREATED", "TCP", "socket",
        config.tcp_local_ip, config.tcp_local_port, "", 0,
        config.tcp_destination_ip, config.tcp_destination_port,
        0, 0, tcp_marker, "TCP socket created");

    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sin_family = AF_INET;
    socket_address.sin_addr = tcp_local_address;
    socket_address.sin_port = htons(config.tcp_local_port);
    result = bind(tcp_socket, (struct sockaddr *)&socket_address, sizeof(socket_address));
    if (result == SOCKET_ERROR)
    {
        wsa_error = WSAGetLastError();
        LOG_OR_FAIL("TCP_BIND_RESULT", "TCP", "bind",
            config.tcp_local_ip, config.tcp_local_port, "", 0,
            config.tcp_destination_ip, config.tcp_destination_port,
            result, wsa_error, tcp_marker, "TCP bind failed");
        exit_code = 21;
        goto cleanup;
    }
    LOG_OR_FAIL("TCP_BIND_RESULT", "TCP", "bind",
        config.tcp_local_ip, config.tcp_local_port, "", 0,
        config.tcp_destination_ip, config.tcp_destination_port,
        result, 0, tcp_marker, "TCP bind succeeded");

    {
        int getsockname_result = 0;
        int getsockname_error = 0;
        BOOL endpoint_matches = inspect_local_endpoint(
            tcp_socket,
            &tcp_local_address,
            config.tcp_local_port,
            tcp_actual_ip,
            &tcp_actual_port,
            &getsockname_result,
            &getsockname_error);
        LOG_OR_FAIL("TCP_GETSOCKNAME", "TCP", "getsockname",
            config.tcp_local_ip, config.tcp_local_port,
            tcp_actual_ip, tcp_actual_port,
            config.tcp_destination_ip, config.tcp_destination_port,
            getsockname_result, getsockname_error, tcp_marker,
            endpoint_matches ? "TCP local endpoint confirmed" : "TCP local endpoint mismatch or query failure");
        if (!endpoint_matches)
        {
            exit_code = 22;
            goto cleanup;
        }
    }

    LOG_OR_FAIL("TCP_CONNECT_BEGIN", "TCP", "connect",
        config.tcp_local_ip, config.tcp_local_port,
        tcp_actual_ip, tcp_actual_port,
        config.tcp_destination_ip, config.tcp_destination_port,
        0, 0, tcp_marker, "TCP connect begin");

    memset(&socket_address, 0, sizeof(socket_address));
    socket_address.sin_family = AF_INET;
    socket_address.sin_addr = tcp_destination_address;
    socket_address.sin_port = htons(config.tcp_destination_port);
    {
        CONNECT_RESULT connect_result = connect_with_timeout(
            tcp_socket,
            &socket_address,
            config.tcp_timeout_ms);
        LOG_OR_FAIL("TCP_CONNECT_RESULT", "TCP", "connect",
            config.tcp_local_ip, config.tcp_local_port,
            tcp_actual_ip, tcp_actual_port,
            config.tcp_destination_ip, config.tcp_destination_port,
            connect_result.return_code,
            connect_result.wsa_error,
            tcp_marker,
            connect_result.detail);
        if (!connect_result.connected)
        {
            exit_code = 23;
            goto cleanup;
        }
    }

    result = send_all(
        tcp_socket,
        tcp_marker,
        (int)strlen(tcp_marker),
        &wsa_error);
    if (result == SOCKET_ERROR)
    {
        LOG_OR_FAIL("TCP_SEND_RESULT", "TCP", "send",
            config.tcp_local_ip, config.tcp_local_port,
            tcp_actual_ip, tcp_actual_port,
            config.tcp_destination_ip, config.tcp_destination_port,
            result, wsa_error, tcp_marker, "TCP marker send failed");
        exit_code = 24;
        goto cleanup;
    }
    LOG_OR_FAIL("TCP_SEND_RESULT", "TCP", "send",
        config.tcp_local_ip, config.tcp_local_port,
        tcp_actual_ip, tcp_actual_port,
        config.tcp_destination_ip, config.tcp_destination_port,
        result, 0, tcp_marker, "TCP marker sent");

    Sleep(config.hold_ms);
    LOG_OR_FAIL("HOLD", "HARNESS", "Sleep",
        "", 0, "", 0, "", 0, 0, 0, "", "Hold completed");

    run_success = TRUE;
    exit_code = 0;

cleanup:
    {
        int cleanup_result = 0;
        int cleanup_error = 0;
        int wsa_cleanup_result = 0;
        int wsa_cleanup_error = 0;

        if (tcp_socket != INVALID_SOCKET)
        {
            result = closesocket(tcp_socket);
            if (result == SOCKET_ERROR)
            {
                cleanup_error = WSAGetLastError();
                cleanup_result = SOCKET_ERROR;
                if (exit_code == 0)
                    exit_code = 30;
            }
            tcp_socket = INVALID_SOCKET;
        }
        if (udp_socket != INVALID_SOCKET)
        {
            result = closesocket(udp_socket);
            if (result == SOCKET_ERROR)
            {
                int close_error = WSAGetLastError();
                if (cleanup_error == 0)
                    cleanup_error = close_error;
                cleanup_result = SOCKET_ERROR;
                if (exit_code == 0)
                    exit_code = 31;
            }
            udp_socket = INVALID_SOCKET;
        }

        if (event_context.file != NULL)
        {
            if (!log_event(&event_context,
                    "CLEANUP", "HARNESS", "closesocket",
                    "", 0, "", 0, "", 0,
                    cleanup_result, cleanup_error, "",
                    cleanup_result == 0 ? "Sockets closed" : "Socket cleanup error",
                    -1))
            {
                fprintf(stderr, "Failed to write JSONL CLEANUP phase.\n");
                if (exit_code == 0)
                    exit_code = 32;
            }
        }

        if (wsa_started)
        {
            wsa_cleanup_result = WSACleanup();
            if (wsa_cleanup_result == SOCKET_ERROR)
            {
                wsa_cleanup_error = WSAGetLastError();
                if (exit_code == 0)
                    exit_code = 33;
            }
            wsa_started = FALSE;
        }

        run_success = run_success &&
            exit_code == 0 &&
            cleanup_result == 0 &&
            wsa_cleanup_result == 0 &&
            udp_seed_confirmed;

        if (event_context.file != NULL)
        {
            char summary_detail[DETAIL_BUFFER_SIZE];
            snprintf(summary_detail, sizeof(summary_detail),
                "success=%d udp_seed_confirmed=%d wsa_cleanup_error=%d",
                run_success ? 1 : 0,
                udp_seed_confirmed ? 1 : 0,
                wsa_cleanup_error);
            if (!log_event(&event_context,
                    "SUMMARY", "HARNESS", "run",
                    "", 0, "", 0, "", 0,
                    exit_code, wsa_cleanup_error, "",
                    summary_detail,
                    run_success ? 1 : 0))
            {
                fprintf(stderr, "Failed to write JSONL SUMMARY phase.\n");
                if (exit_code == 0)
                    exit_code = 34;
            }
            if (fclose(event_context.file) != 0)
            {
                fprintf(stderr, "Failed to close JSONL log: errno=%d\n", errno);
                if (exit_code == 0)
                    exit_code = 35;
            }
            event_context.file = NULL;
        }
    }

#undef LOG_OR_FAIL
    return exit_code;
}
