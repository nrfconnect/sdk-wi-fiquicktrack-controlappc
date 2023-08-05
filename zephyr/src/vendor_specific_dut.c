/* Copyright (c) 2020 Wi-Fi Alliance                                                */

/* Copyright (c) 2023 Nordic semiconductor ASA                                      */

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
void save_wsc_setting(wps_setting *s, char *entry, int len)
{
    /*TODO: Implement this for zephyr */
}

wps_setting* __get_wps_setting(int len, char *buffer, enum wps_device_role role)
{
    /*TODO: Implement this for zephyr */

    return NULL;
}

wps_setting* get_vendor_wps_settings(enum wps_device_role role)
{
    /*TODO: Implement this for zephyr */

    return NULL;
}
#endif /* End Of CONFIG_WPS */
