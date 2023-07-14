/* Copyright (c) 2020 Wi-Fi Alliance                                                */

/* Permission to use, copy, modify, and/or distribute this software for any         */
/* purpose with or without fee is hereby granted, provided that the above           */
/* copyright notice and this permission notice appear in all copies.                */

/* THE SOFTWARE IS PROVIDED 'AS IS' AND THE AUTHOR DISCLAIMS ALL                    */
/* WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED                    */
/* WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL                     */
/* THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR                       */
/* CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING                        */
/* FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF                       */
/* CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT                       */
/* OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS                          */
/* SOFTWARE. */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#ifdef _SYSLOG_
#include <syslog.h>
#endif
#include <fcntl.h>
#include <sys/wait.h>
#include <time.h>
#include <zephyr/net/socket.h>
#include <stdint.h>
typedef uint8_t u_int8_t;
typedef uint16_t u_int16_t;
typedef uint32_t u_int32_t;

#include "vendor_specific.h"
#include "utils.h"
#include "eloop.h"

#define ICMP_ECHO 8
#define ICMP_ECHOREPLY 0
#define usleep(x) k_sleep(K_SECONDS((x)/1000000))

/* Log */
int stdout_level = LOG_LEVEL_DEBUG;
#ifdef _SYSLOG_
int syslog_level = LOG_LEVEL_INFO;
#endif

static struct loopback_info loopback;

void send_continuous_loopback_packet(void *eloop_ctx, void *sock_ctx);

#include <zephyr/net/net_ip.h>

extern char *qt_inet_ntoa(struct in_addr in)
{
	char addr[NET_IPV4_ADDR_LEN];

	return net_addr_ntop(AF_INET, (const void *)&in, addr, NET_IPV4_ADDR_LEN);
}

extern int inet_aton(const char *cp, struct in_addr *addr)
{
    return net_addr_pton(AF_INET, cp, addr);
}

/* lifted from inet_addr.c */
unsigned long inet_addr(register const char *cp)
{
	struct in_addr val;

	if (inet_aton(cp, &val))
		return (val.s_addr);
	return (INADDR_NONE);
}

void debug_print_timestamp(void) {
    time_t rawtime;
    struct tm *info;
    char buffer[32];

    time(&rawtime);
    info = localtime(&rawtime);
    if (info) {
        strftime(buffer, sizeof(buffer), "%b %d %H:%M:%S", info);
    }
    printf("%s ", buffer);
}

void indigo_logger(int level, const char *fmt, ...) {
    char *format, *log_type;
    int maxlen;
#ifdef _SYSLOG_
    int priority;
#endif
    va_list ap;

    maxlen = strlen(fmt) + 100;
    format = malloc(maxlen);
    if (!format) {
        return;
    }

    switch (level) {
    case LOG_LEVEL_DEBUG_VERBOSE:
        log_type = "debugverbose";
        break;
    case LOG_LEVEL_DEBUG:
        log_type = "debug";
        break;
    case LOG_LEVEL_INFO:
        log_type = "info";
        break;
    case LOG_LEVEL_NOTICE:
        log_type = "notice";
        break;
    case LOG_LEVEL_WARNING:
        log_type = "warning";
        break;
    default:
        log_type = "info";
        break;
    }

    snprintf(format, maxlen, "controlappc.%8s  %s", log_type, fmt);

    if (level >= stdout_level) {
        debug_print_timestamp();
        va_start(ap, fmt);
        vprintf(format, ap);
        va_end(ap);
        printf("\n");
    }

#ifdef _SYSLOG_
    if (level >= stdout_level) {
        switch (level) {
        case LOG_LEVEL_DEBUG_VERBOSE:
        case LOG_LEVEL_DEBUG:
                priority = LOG_DEBUG;
                break;
        case LOG_LEVEL_INFO:
                priority = LOG_INFO;
                break;
        case LOG_LEVEL_NOTICE:
                priority = LOG_NOTICE;
                break;
        case LOG_LEVEL_WARNING:
                priority = LOG_WARNING;
                break;
        default:
                priority = LOG_INFO;
                break;
        }
        va_start(ap, fmt);
        vsyslog(priority, format, ap);
        va_end(ap);
    }
#endif
}

int write_file(char *fn, char *buffer, int len) {
    return 0;
}

/* Loopback */
int loopback_socket = 0;

static void loopback_server_receive_message(int sock, void *eloop_ctx, void *sock_ctx) {
    struct sockaddr_storage from;
    unsigned char buffer[BUFFER_LEN];
    ssize_t fromlen, len;

    (void)eloop_ctx;
    (void)sock_ctx;

    fromlen = sizeof(from);
    len = recvfrom(sock, buffer, BUFFER_LEN, 0, (struct sockaddr *) &from, (socklen_t *)&fromlen);
    if (len < 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Loopback server recvfrom[server] error");
        return ;
    }

    indigo_logger(LOG_LEVEL_INFO, "Loopback server received length = %d", len);

    len = sendto(sock, (const char *)buffer, len, MSG_CONFIRM, (struct sockaddr *)&from, sizeof(from));

    indigo_logger(LOG_LEVEL_INFO, "Loopback server echo back length = %d", len);
}

static void loopback_server_timeout(void *eloop_ctx, void *timeout_ctx) {
    int s = (intptr_t)eloop_ctx;

    (void)timeout_ctx;

    qt_eloop_unregister_read_sock(s);
    close(s);
    loopback_socket = 0;
    indigo_logger(LOG_LEVEL_INFO, "Loopback server stops");
}

int loopback_server_start(char *local_ip, char *local_port, int timeout) {
    int s = 0;
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);

   /* Open UDP socket */
    s = socket(PF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to open server socket");
        return -1;
    }

    /* Bind specific IP */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (local_ip) {
        addr.sin_addr.s_addr = inet_addr(local_ip);
    }

    if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to bind server socket");
        close(s);
        return -1;
    }

    if (getsockname(s, (struct sockaddr *)&addr, &len) == -1) {
        indigo_logger(LOG_LEVEL_INFO, "Failed to get socket port number");
        close(s);
        return -1;
    } else {
        indigo_logger(LOG_LEVEL_INFO, "loopback server port number %d\n", ntohs(addr.sin_port));
        sprintf(local_port, "%d", ntohs(addr.sin_port));
    }

    /* Register to eloop and ready for the socket event */
    if (qt_eloop_register_read_sock(s, loopback_server_receive_message, NULL, NULL)) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to initiate ControlAppC");
        return -1;
    }
    loopback_socket = s;
    qt_eloop_register_timeout(timeout, 0, loopback_server_timeout, (void*)(intptr_t)s, NULL);
    indigo_logger(LOG_LEVEL_INFO, "Loopback Client starts ip %s port %s", local_ip, local_port);

    return 0;
}

int loopback_server_stop() {
    if (loopback_socket) {
        qt_eloop_cancel_timeout(loopback_server_timeout, (void*)(intptr_t)loopback_socket, NULL);
        qt_eloop_unregister_read_sock(loopback_socket);
        close(loopback_socket);
        loopback_socket = 0;
    }
    return 0;
}

int loopback_server_status() {
    return !!loopback_socket;
}

unsigned short icmp_chksum(unsigned short *buf, int size)
{
    unsigned long sum = 0;
    while (size > 1) {
        sum += *buf;
        buf++;
        size -= 2;
    }
    if (size == 1)
        sum += *(unsigned char *)buf;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

void setup_icmp_hdr(u_int8_t type, u_int8_t code, u_int16_t id,
    u_int16_t seq, char *pkt, int packet_size)
{
    struct net_icmp_hdr *net_icmp_hdr = (struct net_icmp_hdr *)pkt;

    memset(net_icmp_hdr, 0, sizeof(struct net_icmp_hdr));
    net_icmp_hdr->type = type;
    net_icmp_hdr->code = code;
    net_icmp_hdr->chksum = icmp_chksum((unsigned short *)pkt, packet_size);
}

void send_one_loopback_icmp_packet(struct loopback_info *info) {
    int n;
    char server_reply[1600];
    struct in_addr insaddr;
    struct net_icmp_hdr *recv_net_icmp_hdr;
    struct net_ipv4_hdr *recv_iphdr;
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(info->target_ip);


    info->pkt_sent++;
    setup_icmp_hdr(ICMP_ECHO, 0, 0, info->pkt_sent, &info->message[0], info->pkt_size);

    n = sendto(info->sock, (char *)info->message, info->pkt_size, 0, (struct sockaddr *)&addr, sizeof(addr));
    if (n < 0) {
        indigo_logger(LOG_LEVEL_WARNING, "Send failed on icmp packet %d", info->pkt_sent);
        goto done;
    }
    indigo_logger(LOG_LEVEL_INFO, "Packet %d: Send icmp %d bytes data to ip %s",
                  info->pkt_sent, n, info->target_ip);

    memset(&server_reply, 0, sizeof(server_reply));
    n = recv(info->sock, server_reply, sizeof(server_reply), 0);
    if (n < 0) {
        indigo_logger(LOG_LEVEL_WARNING, "recv failed on icmp packet %d", info->pkt_sent);
        goto done;
    } else {
        recv_iphdr = (struct net_ipv4_hdr *)server_reply;
        recv_net_icmp_hdr = (struct net_icmp_hdr *)(server_reply + (recv_iphdr->vhl << 2));
        memcpy(&insaddr, &recv_iphdr->src, sizeof(struct in_addr));

        if (!strcmp(info->target_ip, qt_inet_ntoa(insaddr)) && recv_net_icmp_hdr->type == ICMP_ECHOREPLY) {
            indigo_logger(LOG_LEVEL_INFO, "icmp echo reply from %s, Receive echo %d bytes data", info->target_ip, n - 20);
            info->pkt_rcv++;
        } else {
            indigo_logger(LOG_LEVEL_INFO, "Received packet is not the ICMP reply from the DUT");
        }
    }

done:
    qt_eloop_register_timeout(0, info->rate * 1000000, send_continuous_loopback_packet, info, NULL);
}

void send_one_loopback_udp_packet(struct loopback_info *info) {
    char server_reply[1600];
    ssize_t recv_len = 0, send_len = 0;

    memset(&server_reply, 0, sizeof(server_reply));

    info->pkt_sent++;
    send_len = send(info->sock, info->message, strlen(info->message), 0);
    if (send_len < 0) {
        indigo_logger(LOG_LEVEL_INFO, "Send failed on packet %d", info->pkt_sent);
        // In case Tool doesn't send stop or doesn't receive stop
        if (info->pkt_sent < 1000)
            qt_eloop_register_timeout(0, info->rate*1000000, send_continuous_loopback_packet, info, NULL);
        return;
    }
    indigo_logger(LOG_LEVEL_INFO, "Packet %d: Send loopback %d bytes data",
            info->pkt_sent, send_len);

    recv_len = recv(info->sock, server_reply, sizeof(server_reply), 0);
    if (recv_len < 0) {
        indigo_logger(LOG_LEVEL_INFO, "recv failed on packet %d", info->pkt_sent);
        // In case Tool doesn't send stop or doesn't receive stop
        if (info->pkt_sent < 1000)
            qt_eloop_register_timeout(0, info->rate*1000000, send_continuous_loopback_packet, info, NULL);
        return;
    }
    info->pkt_rcv++;
    indigo_logger(LOG_LEVEL_INFO, "Receive echo %d bytes data", recv_len);

    qt_eloop_register_timeout(0, info->rate*1000000, send_continuous_loopback_packet, info, NULL);
}

void send_continuous_loopback_packet(void *eloop_ctx, void *sock_ctx) {
    struct loopback_info *info = (struct loopback_info *)eloop_ctx;

    (void)eloop_ctx;
    (void)sock_ctx;

    if (info->pkt_type == DATA_TYPE_ICMP) {
        send_one_loopback_icmp_packet(info);
    } else {
        send_one_loopback_udp_packet(info);
    }
}

/* Stop to send continuous loopback data */
int stop_loopback_data(int *pkt_sent)
{
    if (loopback.sock <= 0)
        return 0;

    qt_eloop_cancel_timeout(send_continuous_loopback_packet, &loopback, NULL);
    close(loopback.sock);
    loopback.sock = 0;
    if (pkt_sent)
        *pkt_sent = loopback.pkt_sent;

    return loopback.pkt_rcv;
}

int send_udp_data(char *target_ip, int target_port, int packet_count, int packet_size, double rate) {
    int s = 0, i = 0;
    struct sockaddr_in addr;
    int pkt_sent = 0, pkt_rcv = 0;
    char message[1600], server_reply[1600];
    char ifname[32];
    ssize_t recv_len = 0, send_len = 0;
    struct timeval timeout;

    /* Open UDP socket */
    s = socket(PF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to open socket");
        return -1;
    }

    if (rate < 1) {
        timeout.tv_sec = 0;
        timeout.tv_usec = rate * 1000000;
    } else {
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
    }
    if (get_p2p_group_if(ifname, sizeof(ifname)) != 0)
        snprintf(ifname, sizeof(ifname), "%s", WIRELESS_INTERFACE_DEFAULT);
    const int len = strlen(ifname);
    if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, ifname, len) < 0) {
        indigo_logger(LOG_LEVEL_ERROR, "failed to bind the interface %s", ifname);
        return -1;
    }

    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    if (target_ip) {
        addr.sin_addr.s_addr = inet_addr(target_ip);
    }
    addr.sin_port = htons(target_port);

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Connect failed. Error");
        close(s);
        return -1;
    }

    indigo_logger(LOG_LEVEL_INFO, "packet_count %d rate %lf\n",
                  packet_count, rate);

    /* Continuous data case: reply OK and use eloop timeout to send data */
    if (packet_count == -1) {
        loopback.sock = s;
        loopback.pkt_type = DATA_TYPE_UDP;
        loopback.rate = rate;
        loopback.pkt_sent = loopback.pkt_rcv = 0;
        memset(loopback.message, 0, sizeof(loopback.message));
        for (i = 0; (i < packet_size) && (i < (int)sizeof(loopback.message)); i++)
            loopback.message[i] = 0x0A;
        qt_eloop_register_timeout(0, 0, send_continuous_loopback_packet, &loopback, NULL);
        indigo_logger(LOG_LEVEL_INFO, "Send continuous loopback data to ip %s port %u",
                      target_ip, target_port);
        return 0;
    }

    memset(message, 0, sizeof(message));
    for (i = 0; (i < packet_size) && (i < (int)sizeof(message)); i++)
        message[i] = 0x0A;

    for (pkt_sent = 1; pkt_sent <= packet_count; pkt_sent++) {
        memset(&server_reply, 0, sizeof(server_reply));

        send_len = send(s, message, strlen(message), 0);
        if (send_len < 0) {
            indigo_logger(LOG_LEVEL_INFO, "Send failed on packet %d", pkt_sent);
            usleep(rate*1000000);
            continue;
        }
        indigo_logger(LOG_LEVEL_INFO, "Packet %d: Send loopback %d bytes data to ip %s port %u",
                      pkt_sent, send_len, target_ip, target_port);

        recv_len = recv(s, server_reply, sizeof(server_reply), 0);
        if (recv_len < 0) {
            indigo_logger(LOG_LEVEL_INFO, "recv failed on packet %d", pkt_sent);
            if (rate > 1)
                usleep((rate-1)*1000000);
            continue;
        }
        pkt_rcv++;
        usleep(rate*1000000);

        indigo_logger(LOG_LEVEL_INFO, "Receive echo %d bytes data", recv_len);
    }
    close(s);

    return pkt_rcv;
}

int send_icmp_data(char *target_ip, int packet_count, int packet_size, double rate)
{
    int n, sock;
    size_t i;
    unsigned char buf[1600], server_reply[1600];
    char ifname[32];
    struct sockaddr_in addr;
    struct in_addr insaddr;
    struct net_icmp_hdr *recv_net_icmp_hdr;
    struct net_ipv4_hdr *recv_iphdr;
    struct timeval timeout;
    int pkt_sent = 0, pkt_rcv = 0;

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sock < 0) {
        return -1;
	}

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(target_ip);

    if (rate < 1) {
        timeout.tv_sec = 0;
        timeout.tv_usec = rate * 1000000;
    } else {
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
    }

    if (get_p2p_group_if(ifname, sizeof(ifname)) != 0)
        snprintf(ifname, sizeof(ifname), "%s", WIRELESS_INTERFACE_DEFAULT);
    const int len = strlen(ifname);
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifname, len) < 0) {
        indigo_logger(LOG_LEVEL_ERROR, "failed to bind the interface %s", ifname);
        return -1;
    }
    indigo_logger(LOG_LEVEL_DEBUG, "Bind the interface %s", ifname);

    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));

    /* Continuous data case: reply OK and use eloop timeout to send data */
    if (packet_count == -1) {
        memset(&loopback, 0, sizeof(loopback));
        loopback.sock = sock;
        loopback.pkt_type = DATA_TYPE_ICMP;
        loopback.rate = rate;
        loopback.pkt_size = packet_size;
        snprintf(loopback.target_ip, sizeof(loopback.target_ip), "%s", target_ip);
        for (i = sizeof(struct net_icmp_hdr); (i < packet_size) && (i < sizeof(loopback.message)); i++)
            loopback.message[i] = 0x0A;
        qt_eloop_register_timeout(0, 0, send_continuous_loopback_packet, &loopback, NULL);
        indigo_logger(LOG_LEVEL_INFO, "Send continuous loopback data to ip %s", loopback.target_ip);
        return 0;
    }

    memset(&buf, 0, sizeof(buf));
    for (i = sizeof(struct net_icmp_hdr); (i < packet_size) && (i < sizeof(buf)); i++)
        buf[i] = 0x0A;

    for (pkt_sent = 1; pkt_sent <= packet_count; pkt_sent++) {
        memset(&server_reply, 0, sizeof(server_reply));
        setup_icmp_hdr(ICMP_ECHO, 0, 0, pkt_sent, &buf[0], packet_size);

        n = sendto(sock, (char *)buf, packet_size, 0, (struct sockaddr *)&addr, sizeof(addr));
        if (n < 0) {
            indigo_logger(LOG_LEVEL_WARNING, "Send failed on icmp packet %d", pkt_sent);
            usleep(rate * 1000000);
            continue;
        }
        indigo_logger(LOG_LEVEL_INFO, "Packet %d: Send icmp %d bytes data to ip %s",
                      pkt_sent, n, target_ip);

        n = recv(sock, server_reply, sizeof(server_reply), 0);
        if (n < 0) {
            indigo_logger(LOG_LEVEL_WARNING, "recv failed on icmp packet %d", pkt_sent);
            if (rate > 1)
                usleep((rate - 1) * 1000000);
            continue;
        } else {
            recv_iphdr = (struct net_ipv4_hdr *)server_reply;
            recv_net_icmp_hdr = (struct net_icmp_hdr *)(server_reply + (recv_iphdr->vhl << 2));
            memcpy(&insaddr, &recv_iphdr->src, sizeof(struct in_addr));

            if (!strcmp(target_ip, qt_inet_ntoa(insaddr)) && recv_net_icmp_hdr->type == ICMP_ECHOREPLY) {
                /* IP header 20 bytes */
                indigo_logger(LOG_LEVEL_INFO, "icmp echo reply from %s, Receive echo %d bytes data", target_ip, n - 20);
                pkt_rcv++;
            } else {
                indigo_logger(LOG_LEVEL_INFO, "Received packet is not the ICMP reply from the Destination");
            }
        }
        usleep(rate * 1000000);
    }

    close(sock);
    return pkt_rcv;
}

int send_broadcast_arp(char *target_ip, int *send_count, int rate) {
    return 0;
}

int find_interface_ip(char *ipaddr, int ipaddr_len, char *name) {
    /*TODO
     * Need to implement this
     */
    return 0;
}

int get_mac_address(char *buffer, int size, char *interface) {

    /*TODO:
     * Need to implement the functionality 
     */
    return 1;
}

int set_mac_address(char *ifname, char *mac) {
    return 0;
}

int add_wireless_interface(char *ifname) {
    return 0;
}

int delete_wireless_interface(char *ifname) {
    return 0;
}

int set_interface_ip(char *ifname, char *ip) {
    return 0;
}

int reset_interface_ip(char *ifname) {
    return 0;
}

void detect_del_arp_entry(char *ip) {
    return;
}

/* Environment */
int service_port = SERVICE_PORT_DEFAULT;

int get_service_port() {
    return service_port;
}

int set_service_port(int port) {
    service_port = port;
    return 0;
}

/* Channel functions */
struct channel_info band_24[] = { {1, 2412}, {2, 2417}, {3, 2422}, {4, 2427}, {5, 2432}, {6, 2437}, {7, 2442}, {8, 2447}, {9, 2452}, {10, 2457}, {11, 2462} };
struct channel_info band_5[] = { {36, 5180}, {40, 5200}, {44, 5220}, {48, 5240}, {52, 5260}, {56, 5280}, {60, 5300}, {64, 5320}, {100, 5500}, {104, 5520}, {108, 5540},
                                 {112, 5560}, {116, 5580}, {120, 5600}, {124, 5620}, {128, 5640}, {132, 5660}, {136, 5680}, {140, 5700}, {144, 5720}, {149, 5745},
                                 {153, 5765}, {157, 5785}, {161, 5805}, {165, 8525} };

int verify_band_from_freq(int freq, int band) {
    struct channel_info *info = NULL;
    int i, size = 0;

    if (band == BAND_24GHZ) {
        info = band_24;
        size = sizeof(band_24)/sizeof(struct channel_info);
    } else if (band == BAND_5GHZ) {
        info = band_5;
        size = sizeof(band_5)/sizeof(struct channel_info);
    } else if (band == BAND_6GHZ) {
        if (freq >= (5950 + 5*1) && freq <= (5950 + 5*233))
            return 0;
        else
            return -1;
    }

    for (i = 0; i < size; i++) {
        if (freq == info[i].freq) {
            return 0;
        }
    }

    return -1;
}

int get_center_freq_index(int channel, int width) {
    if (width == 1) {
        if (channel >= 36 && channel <= 48) {
            return 42;
        } else if (channel <= 64) {
            return 58;
        } else if (channel >= 100 && channel <= 112) {
            return 106;
        } else if (channel <= 128) {
            return 122;
        } else if (channel <= 144) {
            return 138;
        } else if (channel >= 149 && channel <= 161) {
            return 155;
        }
    } else if (width == 2) {
        if (channel >= 36 && channel <= 64) {
            return 50;
        } else if (channel >= 36 && channel <= 64) {
            return 114;
        }
    }
    return 0;
}

int get_6g_center_freq_index(int channel, int width) {
    int chwidth, i;

    if (width == 1) {
        chwidth = 80;
    } else if (width == 2) {
        chwidth = 160;
    } else {
        return channel;
    }

    for (i=1; i<233; i+=chwidth/5) {
        if (channel >= i && channel < i + chwidth/5)
            return i + (chwidth - 20)/10;
    }

    return -1;
}

int is_ht40plus_chan(int chan) {
    if (chan == 36 || chan == 44 || chan == 52 || chan == 60 ||
        chan == 100 || chan == 108 || chan == 116 || chan == 124 ||
        chan == 132 || chan == 140 || chan == 149 || chan == 157)
        return 1;
    else
        return 0;
}

int is_ht40minus_chan(int chan) {
    if (chan == 40 || chan == 48 || chan == 56 || chan == 64 ||
        chan == 104 || chan == 112 || chan == 120 || chan == 128 ||
        chan == 136 || chan == 144 || chan == 153 || chan == 161)
        return 1;
    else
        return 0;
}

int get_key_value(char *value, char *buffer, char *token) {
    char *ptr = NULL, *endptr = NULL;
    char _token[S_BUFFER_LEN];

    if (!value || !buffer || !token) {
        return -1;
    }

    memset(_token, 0, sizeof(_token));
    sprintf(_token, "\n%s=", token);
    ptr = strstr(buffer, _token);
    if (!ptr) {
        sprintf(_token, "%s=", token);
        if (strncmp(buffer, _token, strlen(_token)) == 0) {
            ptr = buffer;
        }
    }

    if (!ptr) {
        return -1;
    }

    ptr += strlen(_token);
    endptr = strstr(ptr, "\n");
    if (endptr) {
        strncpy(value, ptr, endptr - ptr);
    } else {
        strcpy(value, ptr);
    }

    return 0;
}

