/*
** wpa-supplicant-conf.c -- The implemenation of operations of
** wpa_supplicant.conf.
**
** Copyright (C) 2023 FMSoft (http://www.fmsoft.cn)
**
** Author: Vincent Wei (https://github.com/VincentWei)
**
** This file is part of HBDInetd.
**
** HBDInetd is free software: you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation, either version 3 of the License, or
** (at your option) any later version.
**
** HBDInetd is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
** You should have received a copy of the GNU General Public License
** along with this program.  If not, see http://www.gnu.org/licenses/.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wpa-supplicant-conf.h"
#include "wifi.h"
#include "log.h"

#define CMD_BUF_SIZE    256
#define NET_ID_LEN      128

size_t wpa_conf_load_saved_networks(struct netdev_context *ctxt)
{
    char *reply = ctxt->buf;
    size_t reply_len = WIFI_MSG_BUF_SIZE;
    wifi_command(ctxt, "LIST_NETWORKS", reply, &reply_len);

    if (strchr(reply, '\n') != NULL) {
        return true;
    }

    return false;
}

/*
 * get ap(ssid/key_mgmt) status in wpa_supplicant.conf
 * return
 * -1: not exist
 * 1:  exist but not connected
 * 3:  exist and connected; network id in buffer net_id
*/
int wpa_conf_is_ap_exist(struct netdev_context *ctxt,
        const char *ssid, const char *key_mgmt, char *net_id, int *len)
{
    int ret = -1;
    char cmd[CMD_BUF_SIZE];
    char *reply = ctxt->buf, key_reply[128];
    char *pssid_start = NULL, *pssid_end = NULL, *ptr=NULL;
    int flag = 0;

    if (!ssid || !ssid[0]){
        HLOG_ERR("Error: ssid is NULL!\n");
        return -1;
    }

    size_t reply_len = WIFI_MSG_BUF_SIZE;
    ret = wifi_command(ctxt, "LIST_NETWORKS", reply, &reply_len);
    if (ret) {
        HLOG_ERR("do list networks error!\n");
        return -1;
    }

    ptr = reply;
    while((pssid_start=strstr(ptr, ssid)) != NULL){
        char *p_s=NULL, *p_e=NULL, *p=NULL;

        pssid_end = pssid_start + strlen(ssid);
        /* ssid is presuffix of searched network */
        if(*pssid_end != '\t'){
            p_e = strchr(pssid_start, '\n');
            if(p_e != NULL){
                ptr = p_e;
                continue;
            }else{
                break;
            }
        }

        flag = 0;

        p_e = strchr(pssid_start, '\n');
        if(p_e){
            *p_e = '\0';
        }
        p_s = strrchr(ptr, '\n');
        p_s++;

        if(strstr(p_s, "CURRENT")){
            flag = 2;
        }

        p = strtok(p_s, "\t");
        if(p){
            if(net_id != NULL && *len > 0){
                strncpy(net_id, p, *len-1);
                net_id[*len-1] = '\0';
            }
        }

        /* get key_mgmt */
        sprintf(cmd, "GET_NETWORK %s key_mgmt", net_id);
        size_t key_reply_len = sizeof(key_reply);
        ret = wifi_command(ctxt, cmd, key_reply, &key_reply_len);
        if(ret){
            HLOG_ERR("do get network %s key_mgmt error!\n", net_id);
            return -1;
        }

        HLOG_INFO("GET_NETWORK %s key_mgmt reply %s\n", net_id, key_reply);
        HLOG_INFO("key type %s\n", key_mgmt);

        if (strcmp(key_reply, key_mgmt) == 0) {
            flag += 1;
            *len = strlen(net_id);
            break;
        }

        if (p_e == NULL){
            break;
        }
        else {
            *p_e = '\n';
            ptr = p_e;
        }
    }

    return flag;
}

/*
 * ssid to netid
*/
int wpa_conf_ssid2netid(struct netdev_context *ctxt,
        char *ssid, const char *key_mgmt, char *net_id, int *len)
{
    int ret = -1;
    char cmd[CMD_BUF_SIZE];
    char *reply = ctxt->buf, key_reply[128];
    char *pssid_start = NULL, *pssid_end = NULL, *ptr = NULL;
    int flag = 0;

    /* list ap in wpa_supplicant.conf */
    size_t reply_len = WIFI_MSG_BUF_SIZE;
    ret = wifi_command(ctxt, "LIST_NETWORKS", reply, &reply_len);
    if (ret) {
        HLOG_ERR("do list networks error!\n");
        return -1;
    }

    ptr = reply;
    while((pssid_start=strstr(ptr, ssid)) != NULL){
        char *p_s=NULL, *p_e=NULL, *p_t=NULL;

        pssid_end = pssid_start + strlen(ssid);
        /* ssid is presuffix of searched network */
        if(*pssid_end != '\t'){
            p_e = strchr(pssid_start, '\n');
            if(p_e != NULL){
                ptr = p_e;
                continue;
            }else{
                break;
            }
        }

       flag |= (0x01 << 0);

        p_e = strchr(pssid_start, '\n');
        if(p_e){
            *p_e = '\0';
        }
        p_s = strrchr(ptr, '\n');
        p_s++;



        p_t = strchr(p_s, '\t');
        if(p_t){
       int tmp = 0;
            tmp = p_t - p_s;
            if(tmp <= NET_ID_LEN){
            strncpy(net_id, p_s, tmp);
            net_id[tmp] = '\0';
            }
        }

        /* get key_mgmt */
        sprintf(cmd, "GET_NETWORK %s key_mgmt", net_id);
        size_t key_reply_len = sizeof(key_reply);
        ret = wifi_command(ctxt, cmd, key_reply, &key_reply_len);
        if(ret){
            HLOG_ERR("do get network %s key_mgmt error!\n", net_id);
            return -1;
        }

        if (strcmp(key_reply, key_mgmt) == 0){
            flag |= (0x01 << 1);
            *len =  strlen(net_id);
            break;
        }

        if (p_e == NULL){
            break;
        }
        else {
            *p_e = '\n';
            ptr = p_e;
        }
    }

    return flag;
}

/*
 * Get max priority val in wpa_supplicant.conf
 * return
 *-1: error
 * 0: no network
 * >0: max val
 */
int wpa_conf_get_max_priority(struct netdev_context *ctxt)
{
    int  ret = -1;
    int  val = -1, max_val = 0, len = 0;
    char cmd[CMD_BUF_SIZE], *reply = ctxt->buf, priority[32];
    char net_id[NET_ID_LEN+1];
    char *p_n = NULL, *p_t = NULL;

    /* list ap in wpa_supplicant.conf */
    size_t reply_len = WIFI_MSG_BUF_SIZE;
    ret = wifi_command(ctxt, "LIST_NETWORKS", reply, &reply_len);
    if (ret) {
        HLOG_ERR("do list networks error!\n");
        return -1;
    }

    p_n = strchr(reply, '\n');
    while (p_n != NULL){
        p_n++;
        if ((p_t = strchr(p_n, '\t')) != NULL) {
            len = p_t - p_n;
            if (len <= NET_ID_LEN){
                strncpy(net_id, p_n, len);
                net_id[len] = '\0';
            }
        }

        sprintf(cmd, "GET_NETWORK %s priority", net_id);
        size_t priority_reply_len = sizeof(priority);
        ret = wifi_command(ctxt, cmd, priority, &priority_reply_len);
        if (ret) {
            HLOG_ERR("do get network priority error!\n");
            return -1;
        }

        val = atoi(priority);
        if(val >= max_val){
            max_val = val;
        }

        p_n = strchr(p_n, '\n');
    }

    return max_val;
}

static int is_ip_exist(void)
{
    // TODO
    return 0;
}

int wpa_conf_is_ap_connected(struct netdev_context *ctxt, char *ssid, int *len)
{
    int ret = -1;
    char *reply = ctxt->buf;
    char *p_c=NULL, *p_str = NULL;
    char *p_s=NULL, *p_e=NULL, *p=NULL;
    int is_ap_connected = 0;

    size_t reply_len = WIFI_MSG_BUF_SIZE;
    ret = wifi_command(ctxt, "LIST_NETWORKS", reply, &reply_len);
    if (ret) {
        HLOG_ERR("do list networks error!\n");
        return -1;
    }

    p_str = (char *)reply;
    while((p_c=strstr(p_str, "[CURRENT]")) != NULL){

    if(*(p_c + 9) != '\n' && *(p_c + 9) != '\0')
    {
        p_str = p_c+9;
        continue;
    }

        p_e = strchr(p_c, '\n');
        if(p_e){
            *p_e = '\0';
        }

        p_s = strrchr(p_str, '\n');
        p_s++;
        p = strtok(p_s, "\t");
        p = strtok(NULL, "\t");
        if(p){
            if(ssid != NULL && *len > 0){
                strncpy(ssid, p, *len-1);
                ssid[*len-1] = '\0';
                *len = strlen(ssid);
        is_ap_connected = 1;
        break;
            }
        }

    }

    /* check ip exist */
    ret = is_ip_exist();
    if(ret > 0){
            return ret;
    }else{
        return is_ap_connected;
    }
}

int wpa_conf_get_netid_connected(struct netdev_context *ctxt,
        char *net_id, int *len)
{
    int ret = -1;
    char *reply = ctxt->buf;
    char *p_c=NULL;

    size_t reply_len = WIFI_MSG_BUF_SIZE;
    ret = wifi_command(ctxt, "LIST_NETWORKS", reply, &reply_len);
    if(ret){
        HLOG_ERR("do list networks error!\n");
        return -1;
    }

    if ((p_c=strstr(reply, "CURRENT")) != NULL){
        char *p_s=NULL, *p_e=NULL, *p=NULL;
        p_e = strchr(p_c, '\n');
        if(p_e){
            *p_e = '\0';
        }

        p_s = strrchr(reply, '\n');
        p_s++;
        p = strtok(p_s, "\t");
        if(p){
            if(net_id != NULL && *len > 0){
                strncpy(net_id, p, *len-1);
                net_id[*len-1] = '\0';
                *len = strlen(net_id);
            }
        }

        return 1;
    } else {
        return 0;
    }

}

/*
 * 1. link to ap
 * 2. get ip addr
 *
 */
int wpa_conf_get_ap_connected(struct netdev_context *ctxt,
        char *netid, int *len)
{
    int ret = -1;
    char *reply = ctxt->buf;
    char *p_c=NULL;

    size_t reply_len = WIFI_MSG_BUF_SIZE;
    ret = wifi_command(ctxt, "LIST_NETWORKS", reply, &reply_len);
    if (ret) {
        HLOG_ERR("do list networks error!\n");
        return -1;
    }

    if ((p_c = strstr(reply, "CURRENT")) != NULL) {
        char *p_s = NULL, *p_e = NULL, *p = NULL;
        p_e = strchr(p_c, '\n');
        if (p_e) {
            *p_e = '\0';
        }

        p_s = strrchr(reply, '\n');
        p_s++;
        p = strtok(p_s, "\t");
        if (p) {
            if (netid != NULL && *len > 0) {
                strncpy(netid, p, *len-1);
                netid[*len-1] = '\0';
                *len = strlen(netid);
            }
        }
        return 1;
    }

    return 0;
}

int wpa_conf_enable_all_networks(struct netdev_context *ctxt)
{
    int ret = -1, len = 0;
    char cmd[CMD_BUF_SIZE];
    char *reply = ctxt->buf;
    char net_id[NET_ID_LEN+1];
    char *p_n = NULL, *p_t = NULL;

    /* list ap in wpa_supplicant.conf */
    size_t reply_len = WIFI_MSG_BUF_SIZE;
    ret = wifi_command(ctxt, "LIST_NETWORKS", reply, &reply_len);
    if (ret){
        HLOG_ERR("do list networks error!\n");
        return -1;
    }

    p_n = strchr(reply, '\n');
    while(p_n != NULL){
      p_n++;
        if((p_t = strchr(p_n, '\t')) != NULL){
            len = p_t - p_n;
            if(len <= NET_ID_LEN){
               strncpy(net_id, p_n, len);
               net_id[len] = '\0';
            }
        }

        /* cancel saved in wpa_supplicant.conf */
        sprintf(cmd, "ENABLE_NETWORK %s", net_id);
        reply_len = WIFI_MSG_BUF_SIZE;
        ret = wifi_command(ctxt, cmd, reply, &reply_len);
        if (ret) {
            HLOG_ERR("do enable network %s error!\n", net_id);
            return -1;
        }

        p_n = strchr(p_n, '\n');
    }

    /* save config */
    reply_len = WIFI_MSG_BUF_SIZE;
    ret = wifi_command(ctxt, "SAVE_CONFIG", reply, &reply_len);
    if (ret) {
        HLOG_ERR("do save config error!\n");
        return -1;
    }

    return 0;
}

int wpa_conf_remove_all_networks(struct netdev_context *ctxt)
{
    int ret = -1, len = 0;
    char cmd[CMD_BUF_SIZE];
    char *reply = ctxt->buf;
    char net_id[NET_ID_LEN+1] = {0};
    char *p_n = NULL, *p_t = NULL;

    /* list ap in wpa_supplicant.conf */
    size_t reply_len = WIFI_MSG_BUF_SIZE;
    ret = wifi_command(ctxt, "LIST_NETWORKS", reply, &reply_len);
    if (ret) {
        HLOG_ERR("do list networks error!\n");
        return -1;
    }

    p_n = strchr(reply, '\n');
    while(p_n != NULL){
      p_n++;
        if((p_t = strchr(p_n, '\t')) != NULL){
            len = p_t - p_n;
            if(len <= NET_ID_LEN){
               strncpy(net_id, p_n, len);
               net_id[len] = '\0';
            }
        }

        /* cancel saved in wpa_supplicant.conf */
        sprintf(cmd, "REMOVE_NETWORK %s", net_id);
        reply_len = WIFI_MSG_BUF_SIZE;
        ret = wifi_command(ctxt, cmd, reply, &reply_len);
        if(ret){
            HLOG_ERR("do remove network %s error!\n", net_id);
            return -1;
        }

        p_n = strchr(p_n, '\n');
    }

    /* save config */
    reply_len = WIFI_MSG_BUF_SIZE;
    ret = wifi_command(ctxt, "SAVE_CONFIG", reply, &reply_len);
    if (ret) {
        HLOG_ERR("do save config error!\n");
        return -1;
    }

    return 0;
}
