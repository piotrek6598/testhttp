#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <stdbool.h>
#include <assert.h>
#include "err.h"

#define SHORT_REPORT -1
#define HTTP_PORT 80
#define HTTPS_PORT 443
#define MAX_PORT_NUM 65535
#define BUFFER_SIZE 16384

char *RESPONSE_BUFFER;

int convert_and_check_port_num(char *port_num) {
    int num = 0;
    if (port_num == NULL)
        return -1;
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

int create_http_get_request(char *buffer, char *url, FILE *cookies,
                            int buff_size) {
    int used_len = 0, host_len, new_len, cookie_len;
    char *cookie_line = NULL, *dir;
    bool first_cookie = true;
    size_t size;

    dir = strchr(url, '/');
    host_len = (int) (dir == NULL ? strlen(url) : strlen(url) - strlen(dir));

    if (dir == NULL)
        dir = "/\0";

    used_len += (int) strlen(dir) + 15;
    if (used_len >= buff_size)
        return -1;
    if (sprintf(buffer, "GET %s HTTP/1.1\r\n", dir) < 0)
        fatal("sprintf failure");

    new_len = used_len + host_len + 8;
    if (new_len >= buff_size)
        return -1;
    if (sprintf(buffer + used_len, "Host: %.*s\r\n", host_len, url) < 0)
        fatal("sprintf failure");
    used_len = new_len;

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
    free(cookie_line);
    if (!first_cookie) {
        if (used_len + 2 >= buff_size)
            return -1;
        if (sprintf(buffer + used_len, "\r\n") < 0)
            fatal("sprintf failure");
        used_len += 2;
    }

    if (used_len + 19 >= buff_size)
        return -1;
    if (sprintf(buffer + used_len, "Connection: close\r\n") < 0)
        fatal("sprintf failure");
    used_len += 19;

    if (used_len + 2 >= buff_size)
        return -1;
    if (sprintf(buffer + used_len, "\r\n") < 0)
        fatal("sprintf failure");
    return used_len + 2;
}

char *check_and_convert_test_http_address(char *test_http_address) {
    int default_port;
    char *addr, *http_prefix, *port_location, *url;
    size_t addr_len = strlen(test_http_address);

    if (addr_len < 8)
        return NULL;

    http_prefix = strstr(test_http_address, "http");
    if (http_prefix == NULL)
        return NULL;
    if (http_prefix != test_http_address)
        return NULL;

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
    url = (char *) malloc(addr_len * sizeof(char));
    if (url == NULL)
        fatal("Allocation error occurred.");
    strcpy(url, addr);
    return url;
}

int
parse_http_response(bool *reading_msg_body,
                    bool check_response_status, bool *is_chunked,
                    size_t *remain_in_buffer, int *chunk_len_left) {
    char status_code[10];
    char *tmp_line = RESPONSE_BUFFER, *tmp_line_2 = NULL;
    long response_code;
    int CRLF_consumed = 0;
    unsigned long content_size = 0;
    if (check_response_status) {
        char *status_code_and_msg = strchr(RESPONSE_BUFFER, ' ');
        status_code_and_msg++;
        char *status_msg = strchr(status_code_and_msg, ' ');
        if (sprintf(status_code, "%.*s",
                    (int) (strlen(status_code_and_msg) - strlen(status_msg)),
                    status_code_and_msg) < 0) {
            fatal("sprintf failed");
        }
        status_msg++;
        tmp_line = strstr(status_msg, "\r\n");
        if ((response_code = strtol(status_code, NULL, 10)) != 200) {
            printf("%ld %.*s\n", response_code,
                   (int) (strlen(status_msg) - strlen(tmp_line)),
                   status_msg);
            return SHORT_REPORT;
        }
        tmp_line += 2;
    }

    while (tmp_line != NULL) {
        if (*reading_msg_body) {
            //fprintf(stderr, "\n Tmp_line is: \n%s", tmp_line);
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
                        //RESPONSE_BUFFER = tmp_line;
                        memmove(RESPONSE_BUFFER, tmp_line,
                                strlen(tmp_line) + 1);
                        //fprintf(stderr, "%s", tmp_line);
                        //fprintf(stderr,"strlen is: %lu\n%s\n", strlen(tmp_line), tmp_line);
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
                        // Currently chunk is finished.
                        //*chunk_started = false;
                        /*if (*chunk_len_left != 0)
                            fprintf(stderr, "\nparsing chunk\n");
                        else
                            fprintf(stderr, "\nchunked finished\n");*/
                    } else {
                        // We proceed line with chunk's size.
                        //fprintf(stderr, "%s\n", tmp_line);
                        /*
                        fprintf(stderr, "\nparsing chunk size\n");
                        fprintf(stderr, "\nTmp line is:\n%s", tmp_line);*/
                        *chunk_len_left = (int) strtoul(tmp_line, NULL, 16);
                        content_size += *chunk_len_left;
                        //fprintf(stderr, "\nchunks size is: %d", *chunk_len_left);
                        tmp_line = strstr(tmp_line, "\r\n");
                        tmp_line += 2;
                        //*chunk_started = true;
                    }
                } else {
                    // We only need to know content's size.
                    tmp_line_2 = strstr(tmp_line, "\r\n");
                    //printf("TEST: %lu %lu\n", strlen(tmp_line), strlen(tmp_line_2));
                    content_size += strlen(tmp_line) - strlen(tmp_line_2);
                    tmp_line = tmp_line_2;
                    tmp_line += 2;
                }
                *remain_in_buffer = 0;
            }
        } else {
            // We are in header section or HTTP response.
            if (strstr(tmp_line, "\r\n") == NULL) {
                // Line is break in the middle we'll proceed them later.
                if (CRLF_consumed == 0)
                    fatal("too long header in response");
                //RESPONSE_BUFFER = tmp_line;
                memmove(RESPONSE_BUFFER, tmp_line, strlen(tmp_line) + 1);
                //fprintf(stderr, "strlen is: %lu\n%s\n", strlen(tmp_line), tmp_line);
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
                //*remain_in_buffer = 0;
            }
        }
    }/*
    fprintf(stderr, "\n");
    if (*is_chunked)
        fprintf(stderr, "Is chunked: yes, ");
    else
        fprintf(stderr, "Is chunked: no, ");
    if (*reading_msg_body)
        fprintf(stderr, "Is message: yes, ");
    else
        fprintf(stderr, "Is message: no, ");
    if (*chunk_len_left > 0)
        fprintf(stderr, "chunk started: yes, ");
    else
        fprintf(stderr, "chunk started: no, ");
    fprintf(stderr, "%lu\n", *remain_in_buffer);*/
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

    //printf("Host address is: %s\n", host_addr);              // Debug line
    // Checking if address really contains port num and port num is correct.
    port_num = convert_and_check_port_num(port_substr);
    if (port_num == -1)
        fatal("Wrong port number");

    //printf("Port number is: %d\n", port_num);               // Debug line

    // Opening cookies file.
    char *cookies_file = argv[2];
    cookies = fopen(cookies_file, "r");
    if (cookies == NULL)
        fatal("file open failed");

    test_http_address = check_and_convert_test_http_address(argv[3]);

    if (test_http_address == NULL)
        fatal("Not http/https address");

    //printf("Test http address is: %s\n", test_http_address);      // Debug line

    memset(&addr_hints, 0, sizeof(struct addrinfo));
    addr_hints.ai_family = AF_INET;
    addr_hints.ai_socktype = SOCK_STREAM;
    addr_hints.ai_protocol = IPPROTO_TCP;

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

    if (connect(sock, addr_result->ai_addr, addr_result->ai_addrlen) < 0)
        syserr("connect");

    freeaddrinfo(addr_result);

    //printf("\n");                           // Debug line

    int req_len = create_http_get_request(BUFFER, test_http_address, cookies,
                                          BUFFER_SIZE);
    fclose(cookies);
    if (req_len == -1)
        fatal("http request too long");

    //printf("HTTP Request is:\n%s", BUFFER); // Debug line

    if (write(sock, BUFFER, req_len) != req_len)
        syserr("partial / failed write");

    do {
        /*int i;
        for (i = remain_in_buffer; i < 2*BUFFER_SIZE - 1; i++)
            RESPONSE_BUFFER[i] = '\0';*/
        rcv_len = read(sock, (RESPONSE_BUFFER + remain_in_buffer),
                       BUFFER_SIZE - 1);
        if (rcv_len < 0)
            syserr("read");
        memset(RESPONSE_BUFFER + remain_in_buffer + rcv_len, 0,
               2 * BUFFER_SIZE - remain_in_buffer - rcv_len);
        //fprintf(stderr, "%s\n", RESPONSE_BUFFER);
        fprintf(stderr,"%.*s\n", (int) rcv_len, RESPONSE_BUFFER + remain_in_buffer);
        content_len += (int) parse_http_response(&reading_msg_body,
                                                 check_status, &is_chunked,
                                                 &remain_in_buffer,
                                                 &chunk_len_left);
        if (content_len == SHORT_REPORT)
            report_completed = true;
        check_status = false;
        //printf("%.*s", rcv_len, RESPONSE_BUFFER);
    } while (rcv_len > 0 && !report_completed);
    if (!report_completed)
        printf("Dlugosc zasobu: %d\n", content_len);
    if (close(sock) < 0)
        syserr("close");
    free(host_addr);
    free(test_http_address);
    return 0;
}
