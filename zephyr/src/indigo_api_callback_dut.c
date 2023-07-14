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
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include <zephyr/net/net_ip.h>

#include "indigo_api.h"
#include "vendor_specific.h"
#include "utils.h"
#include "wpa_ctrl.h"
#include "indigo_api_callback.h"
#include "hs2_profile.h"

extern struct sockaddr_in *tool_addr;
int sta_configured = 0;
int sta_started = 0;

extern const char *inet_ntop(int af, const void *src, char *dst, size_t size)
{
    if (af == AF_INET) {
        struct in_addr *in = (struct in_addr *)src;
        return net_addr_ntop(af, (const void *)in, dst, size);
    }
    return NULL;
}

void register_apis() {
    /* Basic */
    register_api(API_GET_IP_ADDR, NULL, get_ip_addr_handler);
    register_api(API_GET_MAC_ADDR, NULL, get_mac_addr_handler);
    register_api(API_GET_CONTROL_APP_VERSION, NULL, get_control_app_handler);
    register_api(API_START_LOOP_BACK_SERVER, NULL, start_loopback_server);
    register_api(API_STOP_LOOP_BACK_SERVER, NULL, stop_loop_back_server_handler);
    register_api(API_ASSIGN_STATIC_IP, NULL, assign_static_ip_handler);
    register_api(API_DEVICE_RESET, NULL, reset_device_handler);
    register_api(API_START_DHCP, NULL, start_dhcp_handler);
    register_api(API_STOP_DHCP, NULL, stop_dhcp_handler);
    register_api(API_GET_WSC_PIN, NULL, get_wsc_pin_handler);
    register_api(API_GET_WSC_CRED, NULL, get_wsc_cred_handler);
    /* STA */
    register_api(API_STA_ASSOCIATE, NULL, associate_sta_handler);
    register_api(API_STA_CONFIGURE, NULL, configure_sta_handler);
    register_api(API_STA_DISCONNECT, NULL, stop_sta_handler);
    register_api(API_STA_SEND_DISCONNECT, NULL, send_sta_disconnect_handler);
    register_api(API_STA_REASSOCIATE, NULL, send_sta_reconnect_handler);
    register_api(API_STA_SET_PARAM, NULL, set_sta_parameter_handler);
    register_api(API_STA_SEND_BTM_QUERY, NULL, send_sta_btm_query_handler);
    register_api(API_STA_SEND_ANQP_QUERY, NULL, send_sta_anqp_query_handler);
    register_api(API_STA_SCAN, NULL, sta_scan_handler);
    register_api(API_STA_START_WPS, NULL, start_wps_sta_handler);
    register_api(API_STA_HS2_ASSOCIATE, NULL, set_sta_hs2_associate_handler);
    register_api(API_STA_ADD_CREDENTIAL, NULL, sta_add_credential_handler);
    register_api(API_STA_INSTALL_PPSMO, NULL, set_sta_install_ppsmo_handler);
    /* TODO: Add the handlers */
    register_api(API_STA_SET_CHANNEL_WIDTH, NULL, NULL);
    register_api(API_STA_POWER_SAVE, NULL, NULL);
    register_api(API_P2P_START_UP, NULL, start_up_p2p_handler);
    register_api(API_P2P_FIND, NULL, p2p_find_handler);
    register_api(API_P2P_LISTEN, NULL, p2p_listen_handler);
    register_api(API_P2P_ADD_GROUP, NULL, add_p2p_group_handler);
    register_api(API_P2P_START_WPS, NULL, p2p_start_wps_handler);
    register_api(API_P2P_CONNECT, NULL, p2p_connect_handler);
    register_api(API_P2P_GET_INTENT_VALUE, NULL, get_p2p_intent_value_handler);
    register_api(API_P2P_INVITE, NULL, p2p_invite_handler);
    register_api(API_P2P_STOP_GROUP, NULL, stop_p2p_group_handler);
    register_api(API_P2P_SET_SERV_DISC, NULL, set_p2p_serv_disc_handler);
    register_api(API_P2P_SET_EXT_LISTEN, NULL, set_p2p_ext_listen_handler);
    register_api(API_STA_ENABLE_WSC, NULL, enable_wsc_sta_handler);
}

static int get_control_app_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    char ipAddress[INET_ADDRSTRLEN];
    char buffer[S_BUFFER_LEN];

    snprintf(buffer, sizeof(buffer), "%s", TLV_VALUE_APP_VERSION);

    if (tool_addr) {
        inet_ntop(AF_INET, &(tool_addr->sin_addr), ipAddress, INET_ADDRSTRLEN);
        indigo_logger(LOG_LEVEL_DEBUG, "Tool Control IP address on DUT network path: %s", ipAddress);
    }

    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, TLV_VALUE_STATUS_OK);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(TLV_VALUE_OK), TLV_VALUE_OK);
    fill_wrapper_tlv_bytes(resp, TLV_CONTROL_APP_VERSION, strlen(buffer), buffer);
    return 0;
}

static int reset_device_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int status = TLV_VALUE_STATUS_OK;
    char *message = TLV_VALUE_RESET_OK;

    vendor_device_reset();

    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);

    return 0;
}

// Bytes to DUT : 01 50 06 00 ed ff ff 00 55 0c 31 39 32 2e 31 36 38 2e 31 30 2e 33
// RESP :{<ResponseTLV.STATUS: 40961>: '0', <ResponseTLV.MESSAGE: 40960>: 'Static Ip successfully assigned to wireless interface'}
static int assign_static_ip_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    char buffer[64];
    struct tlv_hdr *tlv = NULL;
    char *ifname = NULL;
    char *message = TLV_VALUE_ASSIGN_STATIC_IP_OK;

    memset(buffer, 0, sizeof(buffer));
    tlv = find_wrapper_tlv_by_id(req, TLV_STATIC_IP);
    if (tlv) {
        memcpy(buffer, tlv->value, tlv->len);
    } else {
        message = "Failed.";
        goto response;
    }

    ifname = WIRELESS_INTERFACE_DEFAULT;

    /*TODO:
     * Need to implement setting IP functionality
     */

response:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, TLV_VALUE_STATUS_OK);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);

    return 0;
}

// Bytes to DUT : 01 50 01 00 ee ff ff
// ACK:  Bytes from DUT : 01 00 01 00 ee ff ff a0 01 01 30 a0 00 15 41 43 4b 3a 20 43 6f 6d 6d 61 6e 64 20 72 65 63 65 69 76 65 64
// RESP: {<ResponseTLV.STATUS: 40961>: '0', <ResponseTLV.MESSAGE: 40960>: '9c:b6:d0:19:40:c7', <ResponseTLV.DUT_MAC_ADDR: 40963>: '9c:b6:d0:19:40:c7'}
static int get_mac_addr_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {

    /* TODO:
     * Need to implement this for zephyr
     */

    return 0;
}

static int start_loopback_server(struct packet_wrapper *req, struct packet_wrapper *resp) {
    char local_ip[256];
    int status = TLV_VALUE_STATUS_NOT_OK;
    char *message = TLV_VALUE_LOOPBACK_SVR_START_NOT_OK;
    char tool_udp_port[16];
    char if_name[32];

    /* Find network interface. If P2P Group or bridge exists, then use it. Otherwise, it uses the initiation value. */
    memset(local_ip, 0, sizeof(local_ip));
    if (get_p2p_group_if(if_name, sizeof(if_name)) == 0 && find_interface_ip(local_ip, sizeof(local_ip), if_name)) {
        indigo_logger(LOG_LEVEL_DEBUG, "use %s", if_name);
    } else if (find_interface_ip(local_ip, sizeof(local_ip), WIRELESS_INTERFACE_DEFAULT)) {
        indigo_logger(LOG_LEVEL_DEBUG, "use %s", WIRELESS_INTERFACE_DEFAULT);
    } else {
        indigo_logger(LOG_LEVEL_ERROR, "No available interface");
        goto done;
    }
    /* Start loopback */
    if (!loopback_server_start(local_ip, tool_udp_port, LOOPBACK_TIMEOUT)) {
        status = TLV_VALUE_STATUS_OK;
        message = TLV_VALUE_LOOPBACK_SVR_START_OK;
    }
done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    fill_wrapper_tlv_bytes(resp, TLV_LOOP_BACK_SERVER_PORT, strlen(tool_udp_port), tool_udp_port);

    return 0;
}

// RESP: {<ResponseTLV.STATUS: 40961>: '0', <ResponseTLV.MESSAGE: 40960>: 'Loopback server in idle state'}
static int stop_loop_back_server_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    /* Stop loopback */
    if (loopback_server_status()) {
        loopback_server_stop();
    }
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, TLV_VALUE_STATUS_OK);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(TLV_VALUE_LOOP_BACK_STOP_OK), TLV_VALUE_LOOP_BACK_STOP_OK);

    return 0;
}

static int get_ip_addr_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int status = TLV_VALUE_STATUS_NOT_OK;
    char *message = NULL;
    char buffer[64];
    struct tlv_hdr *tlv = NULL;
    char value[16], if_name[32];
    int role = 0;

    memset(value, 0, sizeof(value));
    tlv = find_wrapper_tlv_by_id(req, TLV_ROLE);
    if (tlv) {
            memcpy(value, tlv->value, tlv->len);
            role = atoi(value);
    }

    if (role == DUT_TYPE_P2PUT && get_p2p_group_if(if_name, sizeof(if_name)) == 0 && find_interface_ip(buffer, sizeof(buffer), if_name)) {
        status = TLV_VALUE_STATUS_OK;
        message = TLV_VALUE_OK;
    } else if (find_interface_ip(buffer, sizeof(buffer), WIRELESS_INTERFACE_DEFAULT)) {
        status = TLV_VALUE_STATUS_OK;
        message = TLV_VALUE_OK;
    } else {
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_NOT_OK;
    }

    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (status == TLV_VALUE_STATUS_OK) {
        fill_wrapper_tlv_bytes(resp, TLV_DUT_WLAN_IP_ADDR, strlen(buffer), buffer);
    }
    return 0;
}

static int stop_sta_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {

    /*TODO:
     * Need to implement the handler for zephyr
     */

    return 0;
}


static int configure_sta_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {

    /*TODO:
     * Need to implement the handler to work
     * among different platforms
     */

    return 0;
}

static int associate_sta_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {

    /*TODO:
     * Need to implement the handler for zephyr
     */

    return 0;
}

static int send_sta_disconnect_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    struct wpa_ctrl *w = NULL;
    char *message = TLV_VALUE_WPA_S_DISCONNECT_NOT_OK;
    char buffer[256], response[1024];
    int status = TLV_VALUE_STATUS_NOT_OK;
    size_t resp_len;

    /* Open WPA supplicant UDS socket */
    w = wpa_ctrl_open(WIRELESS_INTERFACE_DEFAULT);
    if (!w) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to wpa_supplicant");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_WPA_S_DISCONNECT_NOT_OK;
        goto done;
    }
    /* Send command to hostapd UDS socket */
    memset(buffer, 0, sizeof(buffer));
    sprintf(buffer, "DISCONNECT");
    memset(response, 0, sizeof(response));
    resp_len = sizeof(response) - 1;
    wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
    if (strncmp(response, WPA_CTRL_OK, strlen(WPA_CTRL_OK)) != 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command. Response: %s", response);
        goto done;
    }
    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_WPA_S_DISCONNECT_OK;

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}

static int send_sta_reconnect_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    struct wpa_ctrl *w = NULL;
    char *message = TLV_VALUE_WPA_S_RECONNECT_NOT_OK;
    char buffer[256], response[1024];
    int status = TLV_VALUE_STATUS_NOT_OK;
    size_t resp_len;

    /* Open WPA supplicant UDS socket */
    w = wpa_ctrl_open(WIRELESS_INTERFACE_DEFAULT);
    if (!w) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to wpa_supplicant");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_WPA_S_RECONNECT_NOT_OK;
        goto done;
    }
    /* Send command to hostapd UDS socket */
    memset(buffer, 0, sizeof(buffer));
    sprintf(buffer, "RECONNECT");
    memset(response, 0, sizeof(response));
    resp_len = sizeof(response) - 1;
    wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
    if (strncmp(response, WPA_CTRL_OK, strlen(WPA_CTRL_OK)) != 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command. Response: %s", response);
        goto done;
    }
    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_WPA_S_RECONNECT_OK;

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}

static int set_sta_parameter_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int status = TLV_VALUE_STATUS_NOT_OK;
    size_t resp_len, i;
    char *message = NULL;
    char buffer[BUFFER_LEN];
    char response[BUFFER_LEN];
    char param_name[32];
    char param_value[256];
    struct tlv_hdr *tlv = NULL;
    struct wpa_ctrl *w = NULL;

    /* Open wpa_supplicant UDS socket */
    w = wpa_ctrl_open(WIRELESS_INTERFACE_DEFAULT);
    if (!w) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to wpa_supplicant");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_WPA_S_CTRL_NOT_OK;
        goto done;
    }

    for (i = 0; i < req->tlv_num; i++) {
        memset(param_name, 0, sizeof(param_name));
        memset(param_value, 0, sizeof(param_value));
        tlv = req->tlv[i];
        strcpy(param_name, find_tlv_config_name(tlv->id));
        memcpy(param_value, tlv->value, tlv->len);

        /* Assemble wpa_supplicant command */
        memset(buffer, 0, sizeof(buffer));
        snprintf(buffer, sizeof(buffer), "SET %s %s", param_name, param_value);
        /* Send command to wpa_supplicant UDS socket */
        resp_len = sizeof(response) - 1;
        wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
        /* Check response */
        if (strncmp(response, WPA_CTRL_OK, strlen(WPA_CTRL_OK)) != 0) {
            indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command. Response: %s", response);
            message = TLV_VALUE_WPA_SET_PARAMETER_NO_OK;
            goto done;
        }
    }

    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;
done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}

static int send_sta_btm_query_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int status = TLV_VALUE_STATUS_NOT_OK;
    size_t resp_len;
    char *message = TLV_VALUE_WPA_S_BTM_QUERY_NOT_OK;
    char buffer[1024];
    char response[1024];
    char reason_code[256];
    char candidate_list[256];
    struct tlv_hdr *tlv = NULL;
    struct wpa_ctrl *w = NULL;

    /* Open wpa_supplicant UDS socket */
    w = wpa_ctrl_open(WIRELESS_INTERFACE_DEFAULT);
    if (!w) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to wpa_supplicant");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_WPA_S_CTRL_NOT_OK;
        goto done;
    }
    /* TLV: BTMQUERY_REASON_CODE */
    tlv = find_wrapper_tlv_by_id(req, TLV_BTMQUERY_REASON_CODE);
    if (tlv) {
        memcpy(reason_code, tlv->value, tlv->len);
    } else {
        goto done;
    }

    /* TLV: TLV_CANDIDATE_LIST */
    tlv = find_wrapper_tlv_by_id(req, TLV_CANDIDATE_LIST);
    if (tlv) {
        memcpy(candidate_list, tlv->value, tlv->len);
    }

    memset(buffer, 0, sizeof(buffer));
    sprintf(buffer, "WNM_BSS_QUERY %s", reason_code);
    if (strcmp(candidate_list, "1") == 0) {
        strcat(buffer, " list");
    }

    /* Send command to wpa_supplicant UDS socket */
    resp_len = sizeof(response) - 1;
    wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
    /* Check response */
    if (strncmp(response, WPA_CTRL_OK, strlen(WPA_CTRL_OK)) != 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command. Response: %s", response);
        goto done;
    }
    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}

static int send_sta_anqp_query_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int status = TLV_VALUE_STATUS_NOT_OK;
    char *message = TLV_VALUE_WPA_S_BTM_QUERY_NOT_OK;
    char buffer[1024];
    char response[1024];
    char bssid[256];
    char anqp_info_id[256];
    struct tlv_hdr *tlv = NULL;
    struct wpa_ctrl *w = NULL;
    size_t resp_len, i;
    char *token = NULL;
    char *delimit = ";";
    char realm[S_BUFFER_LEN];

    /* Open wpa_supplicant UDS socket */
    w = wpa_ctrl_open(WIRELESS_INTERFACE_DEFAULT);
    if (!w) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to wpa_supplicant");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_WPA_S_CTRL_NOT_OK;
        goto done;
    }
    // SCAN
    memset(buffer, 0, sizeof(buffer));
    memset(response, 0, sizeof(response));
    sprintf(buffer, "SCAN");
    resp_len = sizeof(response) - 1;
    wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
    /* Check response */
    if (strncmp(response, WPA_CTRL_OK, strlen(WPA_CTRL_OK)) != 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command. Response: %s", response);
        goto done;
    }
    sleep(10);

    /* TLV: BSSID */
    tlv = find_wrapper_tlv_by_id(req, TLV_BSSID);
    if (tlv) {
        memset(bssid, 0, sizeof(bssid));
        memcpy(bssid, tlv->value, tlv->len);
    } else {
        goto done;
    }

    /* TLV: ANQP_INFO_ID */
    tlv = find_wrapper_tlv_by_id(req, TLV_ANQP_INFO_ID);
    if (tlv) {
        memset(anqp_info_id, 0, sizeof(anqp_info_id));
        memcpy(anqp_info_id, tlv->value, tlv->len);
    }

    if (strcmp(anqp_info_id, "NAIHomeRealm") == 0) {
        /* TLV: REALM */
        memset(realm, 0, sizeof(realm));
        tlv = find_wrapper_tlv_by_id(req, TLV_REALM);
        if (tlv) {
            memcpy(realm, tlv->value, tlv->len);
            sprintf(buffer, "HS20_GET_NAI_HOME_REALM_LIST %s realm=%s", bssid, realm);
        } else {
            goto done;
        }
    } else {
        token = strtok(anqp_info_id, delimit);
        memset(buffer, 0, sizeof(buffer));
        sprintf(buffer, "ANQP_GET %s ", bssid);
        while(token != NULL) {
            for (i = 0; i < sizeof(anqp_maps)/sizeof(struct anqp_tlv_to_config_name); i++) {
                if (strcmp(token, anqp_maps[i].element) == 0) {
                    strcat(buffer, anqp_maps[i].config);
                }
            }

            token = strtok(NULL, delimit);
            if (token != NULL) {
                strcat(buffer, ",");
            }
        }
    }

    /* Send command to wpa_supplicant UDS socket */
    resp_len = sizeof(response) - 1;
    wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);

    indigo_logger(LOG_LEVEL_DEBUG, "%s -> resp: %s\n", buffer, response);
    /* Check response */
    if (strncmp(response, WPA_CTRL_OK, strlen(WPA_CTRL_OK)) != 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command. Response: %s", response);
        goto done;
    }
    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}

static int start_up_p2p_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {

    /*TODO:
     * Need to implement this for zephyr
     */

    return 0;
}

static int p2p_find_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    struct wpa_ctrl *w = NULL;
    char buffer[S_BUFFER_LEN], response[BUFFER_LEN];
    size_t resp_len;
    int status = TLV_VALUE_STATUS_NOT_OK;
    char *message = TLV_VALUE_P2P_FIND_NOT_OK;

    /* Open wpa_supplicant UDS socket */
    w = wpa_ctrl_open(WIRELESS_INTERFACE_DEFAULT);
    if (!w) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to wpa_supplicant");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_WPA_S_CTRL_NOT_OK;
        goto done;
    }
    // P2P_FIND
    memset(buffer, 0, sizeof(buffer));
    memset(response, 0, sizeof(response));
    sprintf(buffer, "P2P_FIND");
    resp_len = sizeof(response) - 1;
    wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
    /* Check response */
    if (strncmp(response, WPA_CTRL_OK, strlen(WPA_CTRL_OK)) != 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command. Response: %s", response);
        goto done;
    }
    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}

static int p2p_listen_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    struct wpa_ctrl *w = NULL;
    char buffer[S_BUFFER_LEN], response[BUFFER_LEN];
    size_t resp_len;
    int status = TLV_VALUE_STATUS_NOT_OK;
    char *message = TLV_VALUE_P2P_LISTEN_NOT_OK;

    /* Open wpa_supplicant UDS socket */
    w = wpa_ctrl_open(WIRELESS_INTERFACE_DEFAULT);
    if (!w) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to wpa_supplicant");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_WPA_S_CTRL_NOT_OK;
        goto done;
    }
    // P2P_LISTEN
    memset(buffer, 0, sizeof(buffer));
    memset(response, 0, sizeof(response));
    sprintf(buffer, "P2P_LISTEN");
    resp_len = sizeof(response) - 1;
    wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
    /* Check response */
    if (strncmp(response, WPA_CTRL_OK, strlen(WPA_CTRL_OK)) != 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command. Response: %s", response);
        goto done;
    }
    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}

static int add_p2p_group_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    struct wpa_ctrl *w = NULL;
    char buffer[S_BUFFER_LEN], response[BUFFER_LEN];
    char freq[64], he[16];
    size_t resp_len;
    int status = TLV_VALUE_STATUS_NOT_OK;
    char *message = TLV_VALUE_P2P_ADD_GROUP_NOT_OK;
    struct tlv_hdr *tlv = NULL;

    memset(freq, 0, sizeof(freq));
    /* TLV_FREQUENCY (required) */
    tlv = find_wrapper_tlv_by_id(req, TLV_FREQUENCY);
    if (tlv) {
        memcpy(freq, tlv->value, tlv->len);
    } else {
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_INSUFFICIENT_TLV;
        indigo_logger(LOG_LEVEL_ERROR, "Missed TLV: TLV_FREQUENCY");
        goto done;
    }

    memset(he, 0, sizeof(he));
    tlv = find_wrapper_tlv_by_id(req, TLV_IEEE80211_AX);
    if (tlv)
        snprintf(he, sizeof(he), " he");

    /* Open wpa_supplicant UDS socket */
    w = wpa_ctrl_open(WIRELESS_INTERFACE_DEFAULT);
    if (!w) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to wpa_supplicant");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_WPA_S_CTRL_NOT_OK;
        goto done;
    }

    memset(buffer, 0, sizeof(buffer));
    memset(response, 0, sizeof(response));
    sprintf(buffer, "P2P_GROUP_ADD freq=%s%s", freq, he);
    resp_len = sizeof(response) - 1;
    wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
    /* Check response */
    if (strncmp(response, WPA_CTRL_OK, strlen(WPA_CTRL_OK)) != 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command. Response: %s", response);
        goto done;
    }
    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}

static int stop_p2p_group_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    struct wpa_ctrl *w = NULL;
    char buffer[S_BUFFER_LEN], response[BUFFER_LEN];
    int persist = 0;
    size_t resp_len;
    int status = TLV_VALUE_STATUS_NOT_OK;
    char *message = TLV_VALUE_P2P_ADD_GROUP_NOT_OK;
    struct tlv_hdr *tlv = NULL;
    char if_name[32];

    tlv = find_wrapper_tlv_by_id(req, TLV_PERSISTENT);
    if (tlv) {
        persist = 1;
    }

    /* Open wpa_supplicant UDS socket */
    w = wpa_ctrl_open(WIRELESS_INTERFACE_DEFAULT);
    if (!w) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to wpa_supplicant");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_WPA_S_CTRL_NOT_OK;
        goto done;
    }

    if (get_p2p_group_if(if_name, sizeof(if_name)) != 0) {
        message = "Failed to get P2P Group Interface";
        goto done;
    }
    memset(buffer, 0, sizeof(buffer));
    memset(response, 0, sizeof(response));
    sprintf(buffer, "P2P_GROUP_REMOVE %s", if_name);
    resp_len = sizeof(response) - 1;
    wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
    /* Check response */
    if (strncmp(response, WPA_CTRL_OK, strlen(WPA_CTRL_OK)) != 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command. Response: %s", response);
        goto done;
    }
    if (w) {
        wpa_ctrl_close(w);
        w = NULL;
    }

    if (persist == 1) {
        /* TODO:
	 * Need to implemnet this for zephyr
	 */
    }
    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}

static int p2p_start_wps_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {

    /* TODO:
     * Need to implement the handler for zephyr
     */

    return 0;
}

static int sta_scan_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int status = TLV_VALUE_STATUS_NOT_OK;
    char *message = TLV_VALUE_WPA_S_SCAN_NOT_OK;
    char buffer[1024];
    char response[1024];
    struct wpa_ctrl *w = NULL;
    size_t resp_len;

    /* Open wpa_supplicant UDS socket */
    w = wpa_ctrl_open(WIRELESS_INTERFACE_DEFAULT);
    if (!w) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to wpa_supplicant");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_WPA_S_CTRL_NOT_OK;
        goto done;
    }
    // SCAN
    memset(buffer, 0, sizeof(buffer));
    memset(response, 0, sizeof(response));
    sprintf(buffer, "SCAN");
    resp_len = sizeof(response) - 1;
    wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
    /* Check response */
    if (strncmp(response, WPA_CTRL_OK, strlen(WPA_CTRL_OK)) != 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command. Response: %s", response);
        goto done;
    }
    indigo_logger(LOG_LEVEL_DEBUG, "%s -> resp: %s\n", buffer, response);
    sleep(10);

    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}

static int set_sta_hs2_associate_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int status = TLV_VALUE_STATUS_NOT_OK;
    size_t resp_len;
    char *message = TLV_VALUE_WPA_S_ASSOC_NOT_OK;
    char buffer[BUFFER_LEN];
    char response[BUFFER_LEN];
    char bssid[256];
    struct tlv_hdr *tlv = NULL;
    struct wpa_ctrl *w = NULL;

    /* Open wpa_supplicant UDS socket */
    w = wpa_ctrl_open(WIRELESS_INTERFACE_DEFAULT);
    if (!w) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to wpa_supplicant");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_WPA_S_CTRL_NOT_OK;
        goto done;
    }

    memset(bssid, 0, sizeof(bssid));
    tlv = find_wrapper_tlv_by_id(req, TLV_BSSID);
    if (tlv) {
        memset(bssid, 0, sizeof(bssid));
        memcpy(bssid, tlv->value, tlv->len);
        memset(buffer, 0, sizeof(buffer));
        snprintf(buffer, sizeof(buffer), "INTERWORKING_CONNECT %s", bssid);
    } else {
        memset(buffer, 0, sizeof(buffer));
        snprintf(buffer, sizeof(buffer), "INTERWORKING_SELECT auto");
    }

    /* Send command to wpa_supplicant UDS socket */
    resp_len = sizeof(response) - 1;
    wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
    /* Check response */
    if (strncmp(response, WPA_CTRL_OK, strlen(WPA_CTRL_OK)) != 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command %s.\n Response: %s", buffer, response);
        goto done;
    }
    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;
done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}

static int sta_add_credential_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    char *message = TLV_VALUE_WPA_S_ADD_CRED_NOT_OK;
    char buffer[BUFFER_LEN];
    int status = TLV_VALUE_STATUS_NOT_OK, cred_id, wpa_ret;
    size_t resp_len, i;
    char response[BUFFER_LEN];
    char param_value[256];
    struct tlv_hdr *tlv = NULL;
    struct wpa_ctrl *w = NULL;
    struct tlv_to_config_name* cfg = NULL;

    /* Open wpa_supplicant UDS socket */
    w = wpa_ctrl_open(WIRELESS_INTERFACE_DEFAULT);
    if (!w) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to wpa_supplicant");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_WPA_S_CTRL_NOT_OK;
        goto done;
    }
    /* Assemble wpa_supplicant command */
    memset(buffer, 0, sizeof(buffer));
    snprintf(buffer, sizeof(buffer), "ADD_CRED");
    resp_len = sizeof(response) - 1;
    wpa_ret = wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
    if (wpa_ret < 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command ADD_CRED. Response: %s", response);
        goto done;
    }
    cred_id = atoi(response);

    for (i = 0; i < req->tlv_num; i++) {
        memset(param_value, 0, sizeof(param_value));
        tlv = req->tlv[i];
        cfg = find_tlv_config(tlv->id);
        if (!cfg) {
            continue;
        }
        memcpy(param_value, tlv->value, tlv->len);

        /* Assemble wpa_supplicant command */
        memset(buffer, 0, sizeof(buffer));

        if (cfg->quoted) {
            snprintf(buffer, sizeof(buffer), "SET_CRED %d %s \"%s\"", cred_id, cfg->config_name, param_value);
        } else {
            snprintf(buffer, sizeof(buffer), "SET_CRED %d %s %s", cred_id, cfg->config_name, param_value);
        }
        indigo_logger(LOG_LEVEL_DEBUG, "Execute the command: %s", buffer);
        /* Send command to wpa_supplicant UDS socket */
        resp_len = sizeof(response) - 1;
        wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
        /* Check response */
        if (strncmp(response, WPA_CTRL_OK, strlen(WPA_CTRL_OK)) != 0) {
            indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command. Response: %s", response);
            message = TLV_VALUE_WPA_SET_PARAMETER_NO_OK;
            goto done;
        }
    }

    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_WPA_S_ADD_CRED_OK;

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    return 0;
}

static int set_sta_install_ppsmo_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {

    /* TODO:
     * Need to implement this for zephyr
     */

    return 0;
}

static int p2p_connect_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    struct wpa_ctrl *w = NULL;
    char buffer[S_BUFFER_LEN], response[BUFFER_LEN];
    char pin_code[64];
    char method[16], mac[32], type[16];
    size_t resp_len;
    int status = TLV_VALUE_STATUS_NOT_OK;
    char *message = TLV_VALUE_P2P_CONNECT_NOT_OK;
    struct tlv_hdr *tlv = NULL;
    char go_intent[32], he[16], persist[32];
    int intent_value = P2P_GO_INTENT;

    memset(buffer, 0, sizeof(buffer));
    memset(mac, 0, sizeof(mac));
    memset(method, 0, sizeof(method));
    memset(type, 0, sizeof(type));
    memset(he, 0, sizeof(he));
    memset(persist, 0, sizeof(persist));
    tlv = find_wrapper_tlv_by_id(req, TLV_ADDRESS);
    if (tlv) {
        memcpy(mac, tlv->value, tlv->len);
    } else {
        indigo_logger(LOG_LEVEL_ERROR, "Missed TLV: TLV_ADDRESS");
        goto done;
    }
    tlv = find_wrapper_tlv_by_id(req, TLV_GO_INTENT);
    if (tlv) {
        memset(go_intent, 0, sizeof(go_intent));
        memcpy(go_intent, tlv->value, tlv->len);
        intent_value = atoi(go_intent);
    }
    tlv = find_wrapper_tlv_by_id(req, TLV_P2P_CONN_TYPE);
    if (tlv) {
        memcpy(type, tlv->value, tlv->len);
        if (atoi(type) == P2P_CONN_TYPE_JOIN) {
            snprintf(type, sizeof(type), " join");
            memset(go_intent, 0, sizeof(go_intent));
        } else if (atoi(type) == P2P_CONN_TYPE_AUTH) {
            snprintf(type, sizeof(type), " auth");
            snprintf(go_intent, sizeof(go_intent), " go_intent=%d", intent_value);
        }
    } else {
            snprintf(go_intent, sizeof(go_intent), " go_intent=%d", intent_value);
    }
    tlv = find_wrapper_tlv_by_id(req, TLV_IEEE80211_AX);
    if (tlv) {
            snprintf(he, sizeof(he), " he");
    }
    tlv = find_wrapper_tlv_by_id(req, TLV_PERSISTENT);
    if (tlv) {
            snprintf(persist, sizeof(persist), " persistent");
    }
    tlv = find_wrapper_tlv_by_id(req, TLV_PIN_CODE);
    if (tlv) {
        memset(pin_code, 0, sizeof(pin_code));
        memcpy(pin_code, tlv->value, tlv->len);
        tlv = find_wrapper_tlv_by_id(req, TLV_PIN_METHOD);
        if (tlv) {
            memcpy(method, tlv->value, tlv->len);
        } else {
            indigo_logger(LOG_LEVEL_ERROR, "Missed TLV PIN_METHOD???");
        }
        sprintf(buffer, "P2P_CONNECT %s %s %s%s%s%s%s", mac, pin_code, method, type, go_intent, he, persist);
    } else {
        tlv = find_wrapper_tlv_by_id(req, TLV_WSC_METHOD);
        if (tlv) {
            memcpy(method, tlv->value, tlv->len);
        } else {
            indigo_logger(LOG_LEVEL_ERROR, "Missed TLV WSC_METHOD");
        }
        sprintf(buffer, "P2P_CONNECT %s %s%s%s%s%s", mac, method, type, go_intent, he, persist);
    }
    indigo_logger(LOG_LEVEL_DEBUG, "Command: %s", buffer);

    /* Open wpa_supplicant UDS socket */
    w = wpa_ctrl_open(WIRELESS_INTERFACE_DEFAULT);
    if (!w) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to wpa_supplicant");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_WPA_S_CTRL_NOT_OK;
        goto done;
    }

    memset(response, 0, sizeof(response));
    resp_len = sizeof(response) - 1;
    wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
    if (strncmp(response, WPA_CTRL_OK, strlen(WPA_CTRL_OK)) != 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command. Response: %s", response);
        goto done;
    }
    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}


static int start_dhcp_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int status = TLV_VALUE_STATUS_NOT_OK;
    char *message = TLV_VALUE_START_DHCP_NOT_OK;
    char buffer[S_BUFFER_LEN];
    char ip_addr[32], role[8];
    struct tlv_hdr *tlv = NULL;
    char if_name[32];

    memset(role, 0, sizeof(role));
    tlv = find_wrapper_tlv_by_id(req, TLV_ROLE);
    if (tlv) {
        memcpy(role, tlv->value, tlv->len);
        if (atoi(role) == DUT_TYPE_P2PUT) {
            get_p2p_group_if(if_name, sizeof(if_name));
        } else {
            indigo_logger(LOG_LEVEL_ERROR, "DHCP only supports in P2PUT");
            goto done;
        }
    } else {
        indigo_logger(LOG_LEVEL_ERROR, "Missed TLV: TLV_ROLE");
        goto done;
    }

    /* TLV: TLV_STATIC_IP */
    memset(ip_addr, 0, sizeof(ip_addr));
    tlv = find_wrapper_tlv_by_id(req, TLV_STATIC_IP);
    if (tlv) { /* DHCP Server */
        memcpy(ip_addr, tlv->value, tlv->len);
        if (!strcmp("0.0.0.0", ip_addr)) {
            snprintf(ip_addr, sizeof(ip_addr), DHCP_SERVER_IP);
        }
        snprintf(buffer, sizeof(buffer), "%s/24", ip_addr);
        set_interface_ip(if_name, buffer);
        start_dhcp_server(if_name, ip_addr);
    } else { /* DHCP Client */
        start_dhcp_client(if_name);
    }
    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);

    return 0;
}

static int stop_dhcp_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int status = TLV_VALUE_STATUS_NOT_OK;
    char *message = TLV_VALUE_NOT_OK;
    char role[8];
    struct tlv_hdr *tlv = NULL;
    char if_name[32];

    memset(role, 0, sizeof(role));
    tlv = find_wrapper_tlv_by_id(req, TLV_ROLE);
    if (tlv) {
        memcpy(role, tlv->value, tlv->len);
        if (atoi(role) == DUT_TYPE_P2PUT) {
            if (!get_p2p_group_if(if_name, sizeof(if_name)))
                reset_interface_ip(if_name);
        } else {
            indigo_logger(LOG_LEVEL_ERROR, "DHCP only supports in P2PUT");
            goto done;
        }
    } else {
        indigo_logger(LOG_LEVEL_ERROR, "Missed TLV: TLV_ROLE");
        goto done;
    }

    /* TLV: TLV_STATIC_IP */
    tlv = find_wrapper_tlv_by_id(req, TLV_STATIC_IP);
    if (tlv) { /* DHCP Server */
        stop_dhcp_server();
    } else { /* DHCP Client */
        stop_dhcp_client();
    }

    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);

    return 0;
}


static int get_wsc_pin_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int status = TLV_VALUE_STATUS_NOT_OK;
    char *message = TLV_VALUE_NOT_OK;
    char buffer[64], response[S_BUFFER_LEN];
    struct tlv_hdr *tlv = NULL;
    char value[16];
    int role = 0;
    struct wpa_ctrl *w = NULL;
    size_t resp_len;

    memset(value, 0, sizeof(value));
    tlv = find_wrapper_tlv_by_id(req, TLV_ROLE);
    if (tlv) {
            memcpy(value, tlv->value, tlv->len);
            role = atoi(value);
    } else {
        indigo_logger(LOG_LEVEL_ERROR, "Missed TLV: TLV_ROLE");
        goto done;
    }

    if (role == DUT_TYPE_STAUT || role == DUT_TYPE_P2PUT) {
        sprintf(buffer, "WPS_PIN get");
        w = wpa_ctrl_open(WIRELESS_INTERFACE_DEFAULT);
        if (!w) {
            indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to wpa_supplicant");
            status = TLV_VALUE_STATUS_NOT_OK;
            message = TLV_VALUE_WPA_S_CTRL_NOT_OK;
            goto done;
        }
    } else {
        indigo_logger(LOG_LEVEL_ERROR, "Invalid value in TLV_ROLE");
    }

    memset(response, 0, sizeof(response));
    resp_len = sizeof(response) - 1;
    wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
    if (strncmp(response, WPA_CTRL_FAIL, strlen(WPA_CTRL_FAIL)) == 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command(%s).", buffer);
        goto done;
    }
    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (status == TLV_VALUE_STATUS_OK) {
        fill_wrapper_tlv_bytes(resp, TLV_WSC_PIN_CODE, strlen(response), response);
    }
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}

static int get_p2p_intent_value_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    int status = TLV_VALUE_STATUS_OK;
    char *message = TLV_VALUE_OK;
    char response[S_BUFFER_LEN];

    memset(response, 0, sizeof(response));
    snprintf(response, sizeof(response), "%d", P2P_GO_INTENT);


    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (status == TLV_VALUE_STATUS_OK) {
        fill_wrapper_tlv_bytes(resp, TLV_P2P_INTENT_VALUE, strlen(response), response);
    }
    return 0;
}

static int start_wps_sta_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    struct wpa_ctrl *w = NULL;
    char buffer[S_BUFFER_LEN], response[BUFFER_LEN];
    char pin_code[64];
    size_t resp_len;
    int status = TLV_VALUE_STATUS_NOT_OK;
    char *message = TLV_VALUE_AP_START_WPS_NOT_OK;
    struct tlv_hdr *tlv = NULL;
    int use_dynamic_pin = 0;

    memset(buffer, 0, sizeof(buffer));
    tlv = find_wrapper_tlv_by_id(req, TLV_PIN_CODE);
    if (tlv) {
        memset(pin_code, 0, sizeof(pin_code));
        memcpy(pin_code, tlv->value, tlv->len);
        if (strlen(pin_code) == 1 && atoi(pin_code) == 0) {
            sprintf(buffer, "WPS_PIN any");
            use_dynamic_pin = 1;
        } else if (strlen(pin_code) == 4 || strlen(pin_code) == 8){
            sprintf(buffer, "WPS_PIN any %s", pin_code);
        } else {
            /* Please implement the function to strip the extraneous
            *  hyphen(dash) attached with 4 or 8-digit PIN code, then
            *  start WPS PIN Registration with stripped PIN code.
            * */
            indigo_logger(LOG_LEVEL_ERROR, "Unrecognized PIN: %s", pin_code);
            goto done;
        }
    } else {
        sprintf(buffer, "WPS_PBC");
    }

    /* Open wpa_supplicant UDS socket */
    w = wpa_ctrl_open(WIRELESS_INTERFACE_DEFAULT);
    if (!w) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to wpa_supplicant");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_WPA_S_CTRL_NOT_OK;
        goto done;
    }

    memset(response, 0, sizeof(response));
    resp_len = sizeof(response) - 1;
    wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
    if (strncmp(response, WPA_CTRL_FAIL, strlen(WPA_CTRL_FAIL)) == 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command(%s).", buffer);
        goto done;
    }

    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (status == TLV_VALUE_STATUS_OK && use_dynamic_pin) {
        fill_wrapper_tlv_bytes(resp, TLV_WSC_PIN_CODE, strlen(response), response);
    }
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}

static int get_wsc_cred_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {

    /* TODO:
     * Need to implement this for zephyr
     */

    return 0;
}

static int p2p_invite_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {

    /* TODO:
     * Need to implement this for zephyr
     */

    return 0;
}

static int set_p2p_serv_disc_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {

    /* TODO:
     * Need to implement this for zephyr
     */

    return 0;
}

static int set_p2p_ext_listen_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {
    struct wpa_ctrl *w = NULL;
    char buffer[S_BUFFER_LEN], response[BUFFER_LEN];
    size_t resp_len;
    int status = TLV_VALUE_STATUS_NOT_OK;
    char *message = TLV_VALUE_P2P_SET_EXT_LISTEN_NOT_OK;

    /* Open wpa_supplicant UDS socket */
    w = wpa_ctrl_open(WIRELESS_INTERFACE_DEFAULT);
    if (!w) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to connect to wpa_supplicant");
        status = TLV_VALUE_STATUS_NOT_OK;
        message = TLV_VALUE_WPA_S_CTRL_NOT_OK;
        goto done;
    }
    memset(buffer, 0, sizeof(buffer));
    memset(response, 0, sizeof(response));
    sprintf(buffer, "P2P_EXT_LISTEN 1000 4000");
    resp_len = sizeof(response) - 1;
    wpa_ctrl_request(w, buffer, strlen(buffer), response, &resp_len, NULL);
    /* Check response */
    if (strncmp(response, WPA_CTRL_OK, strlen(WPA_CTRL_OK)) != 0) {
        indigo_logger(LOG_LEVEL_ERROR, "Failed to execute the command. Response: %s", response);
        goto done;
    }
    status = TLV_VALUE_STATUS_OK;
    message = TLV_VALUE_OK;

done:
    fill_wrapper_message_hdr(resp, API_CMD_RESPONSE, req->hdr.seq);
    fill_wrapper_tlv_byte(resp, TLV_STATUS, status);
    fill_wrapper_tlv_bytes(resp, TLV_MESSAGE, strlen(message), message);
    if (w) {
        wpa_ctrl_close(w);
    }
    return 0;
}

static int enable_wsc_sta_handler(struct packet_wrapper *req, struct packet_wrapper *resp) {

    /* TODO:
     * Need to implement this for zephyr
     */

    return 0;
}
