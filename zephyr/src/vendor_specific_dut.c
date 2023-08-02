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
#include <unistd.h>

#include "vendor_specific.h"
#include "utils.h"

void interfaces_init() {
}
/* Be invoked when start controlApp */
void vendor_init() {
}

/* Be invoked when terminate controlApp */
void vendor_deinit() {
}

/* Called by reset_device_hander() */
void vendor_device_reset() {
}

#ifdef CONFIG_AP
/* Called by configure_ap_handler() */
void configure_ap_enable_mbssid() {
    /*TODO: Implement this for zephyr */
}

void configure_ap_radio_params(char *band, char *country, int channel, int chwidth) {
    /*TODO: Implement this for zephyr */
}

/* void (*callback_fn)(void *), callback of active wlans iterator
 *
 * Called by start_ap_handler() after invoking hostapd
 */
void start_ap_set_wlan_params(void *if_info) {
    /*TODO: Implement this for zephyr */
}
#endif /* End Of CONFIG_AP*/

#ifdef CONFIG_P2P
/* Return addr of P2P-device if there is no GO or client interface */
int get_p2p_mac_addr(char *mac_addr, size_t size) {
    /*TODO: Implement this for zephyr */

    return 0;
}

/* Get the name of P2P Group(GO or Client) interface */
int get_p2p_group_if(char *if_name, size_t size) {
    /*TODO: Implement this for zephyr */

    return 0;
}

int get_p2p_dev_if(char *if_name, size_t size) {
    /*TODO: Implement this for zephyr */

    return 0;
}
#endif /* End Of CONFIG_P2P */

/* Append IP range config and start dhcpd */
void start_dhcp_server(char *if_name, char *ip_addr)
{
    /*TODO: Implement this for zephyr */
}

void stop_dhcp_server()
{
    /*TODO: Implement this for zephyr */
}

void start_dhcp_client(char *if_name)
{
    /*TODO: Implement this for zephyr */
}

void stop_dhcp_client()
{
    /*TODO: Implement this for zephyr */
}

#ifdef CONFIG_WPS
wps_setting *p_wps_setting = NULL;
wps_setting customized_wps_settings_ap[AP_SETTING_NUM];
wps_setting customized_wps_settings_sta[STA_SETTING_NUM];

void save_wsc_setting(wps_setting *s, char *entry, int len)
{
    char *p = NULL;

    (void) len;

    p = strchr(entry, '\n');
    if (p)
        p++;
    else
        p = entry;

    sscanf(p, "%[^:]:%[^:]:%s", s->wkey, s->value, s->attr);
}

wps_setting* __get_wps_setting(int len, char *buffer, enum wps_device_role role)
{
    char *token = strtok(buffer , ",");
    wps_setting *s = NULL;
    int i = 0;

    (void) len;

    if (role == WPS_AP) {
        memset(customized_wps_settings_ap, 0, sizeof(customized_wps_settings_ap));
        p_wps_setting = customized_wps_settings_ap;
        while (token != NULL) {
            s = &p_wps_setting[i++];
            save_wsc_setting(s, token, strlen(token));
            token = strtok(NULL, ",");
        }
    } else {
        memset(customized_wps_settings_sta, 0, sizeof(customized_wps_settings_sta));
        p_wps_setting = customized_wps_settings_sta;
        while (token != NULL) {
            s = &p_wps_setting[i++];
            save_wsc_setting(s, token, strlen(token));
            token = strtok(NULL, ",");
        }
    }
    return p_wps_setting;
}

wps_setting* get_vendor_wps_settings(enum wps_device_role role)
{
    /*
     * Please implement the vendor proprietary function to get WPS OOB and required settings.
     * */
#define WSC_SETTINGS_FILE_AP "/tmp/wsc_settings_APUT"
#define WSC_SETTINGS_FILE_STA "/tmp/wsc_settings_STAUT"
    int len = 0;
    char pipebuf[S_BUFFER_LEN];
    char *parameter_ap[] = {"cat", WSC_SETTINGS_FILE_AP, NULL, NULL};
    char *parameter_sta[] = {"cat", WSC_SETTINGS_FILE_STA, NULL, NULL};

    memset(pipebuf, 0, sizeof(pipebuf));
    if (role == WPS_AP) {
        if (0 == access(WSC_SETTINGS_FILE_AP, F_OK)) {
            // use customized ap wsc settings
            len = pipe_command(pipebuf, sizeof(pipebuf), "/usr/bin/cat", parameter_ap);
            if (len) {
                indigo_logger(LOG_LEVEL_INFO, "wsc settings APUT:\n %s", pipebuf);
                return __get_wps_setting(len, pipebuf, WPS_AP);
            } else {
                indigo_logger(LOG_LEVEL_INFO, "wsc settings APUT: no data");
            }
        } else {
            indigo_logger(LOG_LEVEL_ERROR, "APUT: WPS Erorr. Failed to get settings.");
            return NULL;
        }
    } else {
        if (0 == access(WSC_SETTINGS_FILE_STA, F_OK)) {
            // use customized sta wsc settings
            len = pipe_command(pipebuf, sizeof(pipebuf), "/usr/bin/cat", parameter_sta);
            if (len) {
                indigo_logger(LOG_LEVEL_INFO, "wsc settings STAUT:\n %s", pipebuf);
                return __get_wps_setting(len, pipebuf, WPS_STA);
            } else {
                indigo_logger(LOG_LEVEL_INFO, "wsc settings STAUT: no data");
            }
        } else {
            indigo_logger(LOG_LEVEL_ERROR, "STAUT: WPS Erorr. Failed to get settings.");
            return NULL;
        }
    }

    return NULL;
}
#endif /* End Of CONFIG_WPS */
