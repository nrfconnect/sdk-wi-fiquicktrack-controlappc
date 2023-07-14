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

/* Return addr of P2P-device if there is no GO or client interface */
int get_p2p_mac_addr(char *mac_addr, size_t size) {
    (void) mac_addr;
    (void) size;

    /*TODO
     * Need to implement this for zephyr
     */

    return 1;
}

/* Get the name of P2P Group(GO or Client) interface */
int get_p2p_group_if(char *if_name, size_t size) {
    (void) if_name;
    (void) size;

    /*TODO
     * Need to implement this for zephyr
     */
    return 1;
}

/* "iw dev" doesn't show the name of P2P device. The naming rule is based on wpa_supplicant */
int get_p2p_dev_if(char *if_name, size_t size) {

    /*TODO
     * Need to implement this for zephyr
     */
    return 0;
}

/* Append IP range config and start dhcpd */
void start_dhcp_server(char *if_name, char *ip_addr)
{
    /*TODO
     * Need to implement this for zephyr
     */
}

void stop_dhcp_server()
{
    /*TODO
     * Need to implement this for zephyr
     */
}

void start_dhcp_client(char *if_name)
{
    /*TODO
     * Need to implement this for zephyr
     */
}

void stop_dhcp_client()
{
    /*TODO
     * Need to implement this for zephyr
     */
}

