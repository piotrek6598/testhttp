/** @file
 * Implementation of testhttp_raw binary.
 *
 * @author Piotr Jasinski <jasinskipiotr99@gmail.com
 * @date 26.04.2020
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <stdbool.h>
#include <assert.h>
#include "err.h"

/**
 * Macro defining code returned by @ref parse_http_response when response status
 * is not 200 OK.
 */
#define SHORT_REPORT -1

/**
 * Macro defining default HTTP port.
 */
#define HTTP_PORT 80

/**
 * Macro defining default HTTPS port.
 */
#define HTTPS_PORT 443

/**
 * Macro defining maximum available port number.
 */
#define MAX_PORT_NUM 65535

/**
 * Macro defining default buffer size.
 */
#define BUFFER_SIZE 8192

/**
 * Buffer where HTTP response is stored.
 */
char *RESPONSE_BUFFER;

/** @brief Converts string with port number to int.
 * Expected argument format is e.g. ":80". If port number is invalid
 * or doesn't match given format returns -1.
 * @param port_num [in,out]  - string representing port number.
 * @return Port number or -1 if port number is invalid or doesn't match
 * specified format.
 */
int convert_and_check_port_num(char *port_num) {
    int num = 0;

    if (port_num == NULL)
        return -1;
    // Skipping ':'.
    port_num++;

    while (*port_num != '\0') {
        if (*port_num < '0')
            return -1;
        if (*port_num > '9')
            return -1;
        num *= 10;
        num += (*port_num - '0');
        if (num > MAX_PORT_NUM)
            return -1;
        port_num++;
    }

    return num;
}

/** @brief Creates HTTP GET request.
 * Writes created request to given buffer. If request is larger than buffer size
 * returns -1, but buffer is modified. Assumes that url is in format:
 * <address>[/dir] like: mimuw.edu.pl:80[/file] where [] is optional
 * and given cookies file is open. Splits url by first occurrence of '/'.
 * In case of success returns size of created request.
 * @param buffer [in,out]  - pointer to buffer,
 * @param url [in]         - pointer to url,
 * @param cookies [in]     - pointer to opened file with cookies,
 * @param buff_size [in]   - buffer size.
 * @return Size of created request or -1 if request is too long.
 */
int create_http_get_request(char *buffer, char *url, FILE *cookies,
                            int buff_size) {
    int used_len = 0, host_len, new_len, cookie_len;
    char *cookie_line = NULL, *dir;
    bool first_cookie = true;
    size_t size;

    // Splitting url, by first occurrence of '/'.
    dir = strchr(url, '/');
    host_len = (int) (dir == NULL ? strlen(url) : strlen(url) - strlen(dir));

    if (dir == NULL)
        dir = "/\0";

    used_len += (int) strlen(dir) + 15;
    if (used_len >= buff_size)
        return -1;
    if (sprintf(buffer, "GET %s HTTP/1.1\r\n", dir) < 0)
        fatal("sprintf failure");

    // Creating host header.
    new_len = used_len + host_len + 8;
    if (new_len >= buff_size)
        return -1;
    if (sprintf(buffer + used_len, "Host: %.*s\r\n", host_len, url) < 0)
        fatal("sprintf failure");
    used_len = new_len;

    // Reading cookies from file.
    while (getline(&cookie_line, &size, cookies) != -1) {
        cookie_len = (int) strlen(cookie_line);
        if (strrchr(cookie_line, '\n') != NULL)
            cookie_len--;
        if (first_cookie) {
            new_len = used_len + cookie_len + 8;
            if (new_len >= buff_size)
                return -1;
            if (sprintf(buffer + used_len, "Cookie: %.*s", cookie_len,
                        cookie_line) < 0) {
                fatal("sprintf failure");
            }
            used_len = new_len;
            first_cookie = false;
        } else {
            new_len = used_len + cookie_len + 2;
            if (new_len >= buff_size)
                return -1;
            if (sprintf(buffer + used_len, "; %.*s",
                        cookie_len, cookie_line) < 0) {
                fatal("sprintf failure");
            }
            used_len = new_len;
        }
    }
    // Frees memory allocated for line from cookies file.
    free(cookie_line);
    // Ending cookie header if any cookie was set.
    if (!first_cookie) {
        if (used_len + 2 >= buff_size)
            return -1;
        if (sprintf(buffer + used_len, "\r\n") < 0)
            fatal("sprintf failure");
        used_len += 2;
    }

    // Requesting to end connection after sending response.
    if (used_len + 19 >= buff_size)
        return -1;
    if (sprintf(buffer + used_len, "Connection: close\r\n") < 0)
        fatal("sprintf failure");
    used_len += 19;

    // Ending request.
    if (used_len + 2 >= buff_size)
        return -1;
    if (sprintf(buffer + used_len, "\r\n") < 0)
        fatal("sprintf failure");
    return used_len + 2;
}

/** @brief Checks and converts tested address.
 * Checks if given address is http or https request. If address doesn't contain
 * port number inserts default port.
 * Converted address is copied and allocated, need to be freed later.
 * @param test_http_address [in,out]  - pointer to tested address.
 * @return Pointer to converted address or NULL if address is invalid.
 */
char *check_and_convert_test_http_address(char *test_http_address) {
    int default_port;
    char *addr, *http_prefix, *port_location, *url;
    size_t addr_len = strlen(test_http_address);

    // Address doesn't contain http:// at least.
    if (addr_len < 8)
        return NULL;

    // Address doesn't start with http
    http_prefix = strstr(test_http_address, "http");
    if (http_prefix == NULL)
        return NULL;
    if (http_prefix != test_http_address)
        return NULL;

    // Checking if address starts with http:// or https://
    http_prefix = strstr(test_http_address, "http://");
    if (http_prefix == NULL) {
        http_prefix = strstr(test_http_address, "https://");
        if (http_prefix == NULL)
            return NULL;
        default_port = HTTPS_PORT;
        addr = test_http_address + 8;
        addr_len -= 8;
    } else {
        default_port = HTTP_PORT;
        addr = test_http_address + 7;
        addr_len -= 7;
    }
    // Inserting port number if it's needed.
    if (strchr(addr, ':') == NULL) {
        if (default_port == HTTP_PORT)
            addr_len += 3;
        else
            addr_len += 4;

        url = (char *) malloc((addr_len + 1) * sizeof(char));
        if (url == NULL)
            fatal("Allocation error occurred.");

        port_location = strchr(addr, '/');
        if (port_location == NULL) {
            sprintf(url, "%.*s:%d", (int) addr_len, addr,
                    default_port);
            return url;
        }

        sprintf(url, "%.*s:%d%s", (int) (strlen(addr) - strlen(port_location)),
                addr, default_port, port_location);
        return url;
    }

    // Copying address.
    url = (char *) malloc(addr_len * sizeof(char));
    if (url == NULL)
        fatal("Allocation error occurred.");
    strcpy(url, addr);

    return url;
}

/** @brief Parses http response.
 * If is assigned to treat first line as response status, checks it and
 * if status is not 200 OK return @ref SHORT_REPORT. Otherwise counts
 * and returns content size. Assumes that response is stored
 * in @p RESPONSE_BUFFER. If there are Set-Cookie headers, print to stdout
 * report about set cookies in key=value format. If Transfer-Encoding is
 * chunked marks @p is_chunked. If response in buffer doesn't end with CRLF,
 * text after last CRLF remains in buffer not parsed. If end of header section
 * is detected, marks that message body starts. Before end, sets number
 * of character not parsed and remained in buffer and in case of chunked encoding
 * sets how many characters of started chunk is later expected.
 * Doesn't parse responses with header longer than 2 * @ref BUFFER_SIZE
 * (by default 16kB).
 * @param reading_msg_body [in,out]   - pointer to flag indicating
 *                                      if content is parsed,
 * @param check_response_status [in]  - flag indicating checking response status,
 * @param is_chunked [in,out]         - flag indicating if transfer is chunked,
 * @param remain_in_buffer [in,out]   - pointer to number of remaining
 *                                      characters in buffer,
 * @param chunk_len_left [in,out]     - pointer to number of expected chunk's
 *                                      characters.
 * @return Value @ref SHORT_REPORT if @p check_response_status is true
 * and status is not 200 OK. Otherwise, if transfer is chunked, sum of chunks
 * size defined in beginning of chunks or if transfer is not chunked, length
 * of content.
 */
int parse_http_response(bool *reading_msg_body,
                        bool check_response_status, bool *is_chunked,
                        size_t *remain_in_buffer, int *chunk_len_left) {
    char status_code[10];
    char *tmp_line = RESPONSE_BUFFER, *tmp_line_2 = NULL;
    long response_code;
    int CRLF_consumed = 0;
    unsigned long content_size = 0;

    // Treating first line as status line.
    if (check_response_status) {
        // Skipping HTTP/version.
        char *status_code_and_msg = strchr(RESPONSE_BUFFER, ' ');
        status_code_and_msg++;

        // Extracting status code.
        char *status_msg = strchr(status_code_and_msg, ' ');
        if (sprintf(status_code, "%.*s",
                    (int) (strlen(status_code_and_msg) - strlen(status_msg)),
                    status_code_and_msg) < 0) {
            fatal("sprintf failed");
        }
        status_msg++;

        // Extracting status description.
        tmp_line = strstr(status_msg, "\r\n");
        if ((response_code = strtol(status_code, NULL, 10)) != 200) {
            printf("%ld %.*s\n", response_code,
                   (int) (strlen(status_msg) - strlen(tmp_line)),
                   status_msg);
            return SHORT_REPORT;
        }
        tmp_line += 2;
    }

    // Parsing response. One loop turnover parses one line ended with CRLF.
    while (tmp_line != NULL) {
        if (*reading_msg_body) {
            // We are in content section.
            if (strstr(tmp_line, "\r\n") == NULL) {
                // Line is broken in the middle.
                if (*is_chunked) {
                    // We are in chunk transfer.
                    if (*chunk_len_left > 0) {
                        // We don't use information in chunk so we skip it.
                        *chunk_len_left -= (int) strlen(tmp_line);
                        tmp_line = NULL;
                        *remain_in_buffer = 0;
                    } else {
                        // Line with chunk's size is broken, we'll proceed them later.
                        memmove(RESPONSE_BUFFER, tmp_line,
                                strlen(tmp_line) + 1);
                        *remain_in_buffer = strlen(tmp_line);
                        tmp_line = NULL;
                    }
                } else {
                    // We only need to know content's size.
                    content_size += strlen(tmp_line);
                    tmp_line = NULL;
                    *remain_in_buffer = 0;
                }
            } else {
                // Line ends so we proceed them.
                if (*is_chunked) {
                    // We are in chunk transfer.
                    if (*chunk_len_left > 0) {
                        // We don't use information from line with chunk's content.
                        tmp_line_2 = strstr(tmp_line, "\r\n");
                        *chunk_len_left -= (int) (strlen(tmp_line) -
                                                  strlen(tmp_line_2));
                        tmp_line = tmp_line_2;
                        if (*chunk_len_left != 0)
                            *chunk_len_left -= 2;
                        tmp_line += 2;
                    } else {
                        // We proceed line with chunk's size.
                        *chunk_len_left = (int) strtoul(tmp_line, NULL, 16);
                        content_size += *chunk_len_left;
                        tmp_line = strstr(tmp_line, "\r\n");
                        tmp_line += 2;
                    }
                } else {
                    // We only need to know content's size.
                    tmp_line_2 = strstr(tmp_line, "\r\n");
                    content_size += strlen(tmp_line) - strlen(tmp_line_2) + 2;
                    tmp_line = tmp_line_2;
                    tmp_line += 2;
                }
                *remain_in_buffer = 0;
            }
        } else {
            // We are in header section of HTTP response.
            if (strstr(tmp_line, "\r\n") == NULL) {
                // Line is break in the middle we'll proceed them later.

                // Header is too long
                if (CRLF_consumed == 0)
                    fatal("too long header in response");
                memmove(RESPONSE_BUFFER, tmp_line, strlen(tmp_line) + 1);
                *remain_in_buffer = strlen(tmp_line);
                tmp_line = NULL;
            } else {
                // Line ends so we proceed them.
                CRLF_consumed++;
                if (strstr(tmp_line, "Set-Cookie:") == tmp_line) {
                    // Printing information about cookie.
                    tmp_line = strchr(tmp_line, ' ');
                    tmp_line++;
                    tmp_line_2 = strchr(tmp_line, ';');
                    if (tmp_line_2 == NULL) {
                        tmp_line_2 = strstr(tmp_line, "\r\n");
                        if (tmp_line_2 == NULL)
                            fatal("line unexpectedly broken");
                    }
                    printf("%.*s\n",
                           (int) (strlen(tmp_line) - strlen(tmp_line_2)),
                           tmp_line);
                } else if (strstr(tmp_line, "Transfer-Encoding: chunked") ==
                           tmp_line) {
                    // Setting transfer encoding as chunked.
                    *is_chunked = true;
                } else if (strstr(tmp_line, "\r\n") == tmp_line) {
                    // Empty line, we're starting reading content.
                    *reading_msg_body = true;
                }
                // Skipping rest of line.
                tmp_line = strstr(tmp_line, "\r\n");
                tmp_line += 2;
            }
        }
    }

    assert(*remain_in_buffer < BUFFER_SIZE);
    return (int) content_size;
}

int main(int argc, char *argv[]) {
    int sock;
    struct addrinfo addr_hints;
    struct addrinfo *addr_result;

    FILE *cookies;
    char *port_substr, *host_addr, *test_http_address;
    size_t host_addr_len, remain_in_buffer = 0;
    int port_num, err, rcv_len, content_len = 0, chunk_len_left = 0;
    bool report_completed = false, is_chunked = false, check_status = true;
    bool reading_msg_body = false;

    char BUFFER[BUFFER_SIZE];

    RESPONSE_BUFFER = malloc(2 * BUFFER_SIZE);
    if (RESPONSE_BUFFER == NULL)
        fatal("Allocation error occurred");

    // Checking number of arguments.
    if (argc != 4) {
        fatal("Usage: %s <host>:<port> <cookies file> <testing http address>",
              argv[0]);
    }

    // Splitting argv[0] to host address and port num.
    port_substr = strrchr(argv[1], ':');

    if (port_substr == NULL)
        fatal("Port number not found");

    host_addr_len = strlen(argv[1]) - strlen(port_substr);
    host_addr = (char *) malloc((host_addr_len + 1) * sizeof(char));

    if (host_addr == NULL)
        fatal("Allocation error occurred");

    sprintf(host_addr, "%.*s", (int) host_addr_len, argv[1]);

    // Checking if address really contains port num and port num is correct.
    port_num = convert_and_check_port_num(port_substr);
    if (port_num == -1)
        fatal("Wrong port number");

    // Opening cookies file.
    char *cookies_file = argv[2];
    cookies = fopen(cookies_file, "r");
    if (cookies == NULL)
        fatal("file open failed");

    test_http_address = check_and_convert_test_http_address(argv[3]);

    if (test_http_address == NULL)
        fatal("Not http/https address");

    memset(&addr_hints, 0, sizeof(struct addrinfo));
    addr_hints.ai_family = AF_INET;
    addr_hints.ai_socktype = SOCK_STREAM;
    addr_hints.ai_protocol = IPPROTO_TCP;

    // Getting host address.
    err = getaddrinfo(host_addr, ++port_substr, &addr_hints, &addr_result);
    if (err == EAI_SYSTEM) {
        syserr("getaddrinfo: %s", gai_strerror(err));
    } else if (err != 0) {
        fatal("getaddrinfo: %s", gai_strerror(err));
    }

    sock = socket(addr_result->ai_family, addr_result->ai_socktype,
                  addr_result->ai_protocol);
    if (sock < 0)
        syserr("socket");

    // Connecting to host.
    if (connect(sock, addr_result->ai_addr, addr_result->ai_addrlen) < 0)
        syserr("connect");

    freeaddrinfo(addr_result);

    int req_len = create_http_get_request(BUFFER, test_http_address, cookies,
                                          BUFFER_SIZE);
    if (req_len == -1)
        fatal("http request too long");

    // Closing file with cookies, we don't need it further.
    fclose(cookies);

    // Sending request.
    if (write(sock, BUFFER, req_len) != req_len)
        syserr("partial / failed write");

    do {
        // Getting response.
        rcv_len = read(sock, (RESPONSE_BUFFER + remain_in_buffer),
                       BUFFER_SIZE - 1);
        if (rcv_len < 0)
            syserr("read");

        if (rcv_len == 0 && !reading_msg_body)
            fatal("server closed connection");

        // Filling rest of buffer with 0.
        memset(RESPONSE_BUFFER + remain_in_buffer + rcv_len, 0,
               2 * BUFFER_SIZE - remain_in_buffer - rcv_len);
        // Parsing response.
        content_len += parse_http_response(&reading_msg_body,
                                           check_status, &is_chunked,
                                           &remain_in_buffer,
                                           &chunk_len_left);
        if (content_len == SHORT_REPORT)
            report_completed = true;
        check_status = false;
    } while (rcv_len > 0 && !report_completed);

    if (!report_completed)
        printf("Content length: %d\n", content_len);

    if (close(sock) < 0)
        syserr("close");

    free(host_addr);
    free(test_http_address);
    return 0;
}
