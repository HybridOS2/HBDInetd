#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <wifi_intf.h>
#include <pthread.h>
#include <sys/types.h>
#include <dirent.h>

#include <hbdbus/hbdbus.h>

#include "wifi_intf.h"
#include "inetd.h"

#ifdef PLATFORM_R818
#define CONFIG_CTRL_IFACE_DIR "/etc/wifi/sockets"
#else
#define CONFIG_CTRL_IFACE_DIR "/var/run/wpa_supplicant"
#endif

static hiWiFiDeviceOps wifiOps;

static const char *ctrl_iface_dir = CONFIG_CTRL_IFACE_DIR;
static int event = WIFIMG_NETWORK_DISCONNECTED;

static int change_string(char * src, int src_length, unsigned char * dest, int dest_length)
{
    int i = 0;
    int j = 0;
    unsigned char tempchar = 0;

    if((src == NULL) || (dest == NULL))
        return -1;

    memset(dest, 0, dest_length);
    for(i = 0, j = 0; ((i < src_length) && (j < dest_length)); i++, j++)
    {
        if(*(src + i) == '\\')
        {
            i ++;
            if(i >= src_length)
                break;

            if(*(src + i) == 'x')
            {
                i ++;
                if(i >= src_length)
                    break;
                if((*(src + i) >= '0') && (*(src + i) <= '9'))
                    tempchar = (*(src + i) - '0') << 4;
                else if((*(src + i) >= 'a') && (*(src + i) <= 'f'))
                    tempchar = (*(src + i) - 'a' + 0x0a) << 4;

                i ++;
                if(i >= src_length)
                    break;
                if((*(src + i) >= '0') && (*(src + i) <= '9'))
                    tempchar |= (*(src + i) - '0');
                else if((*(src + i) >= 'a') && (*(src + i) <= 'f'))
                    tempchar |= (*(src + i) - 'a' + 0x0a);

                *(dest + j) = tempchar;
            }
            else
            {
                *(dest + j) = '\\';
                j ++;
                if(j >= dest_length)
                    break;
                *(dest + j) = *(src + i);
            }

        }
        else
            *(dest + j) = *(src + i);
    }
    return 0;
}

static void wifi_event_handle(tWIFI_EVENT wifi_event, void *buf, int event_label)
{
    switch(wifi_event)
    {
        case WIFIMG_WIFI_ON_SUCCESS:
        {
            printf("WiFi on success!\n");
            event = WIFIMG_WIFI_ON_SUCCESS;
            break;
        }

        case WIFIMG_WIFI_ON_FAILED:
        {
            printf("WiFi on failed!\n");
            event = WIFIMG_WIFI_ON_FAILED;
            break;
        }

        case WIFIMG_WIFI_OFF_FAILED:
        {
            printf("wifi off failed!\n");
            event = WIFIMG_WIFI_OFF_FAILED;
            break;
        }

        case WIFIMG_WIFI_OFF_SUCCESS:
        {
            printf("wifi off success!\n");
            event = WIFIMG_WIFI_OFF_SUCCESS;
            break;
        }

        case WIFIMG_NETWORK_CONNECTED:
        {
            printf("WiFi connected ap!\n");
            event = WIFIMG_NETWORK_CONNECTED;
            break;
        }

        case WIFIMG_NETWORK_DISCONNECTED:
        {
            printf("WiFi disconnected!\n");
            event = WIFIMG_NETWORK_DISCONNECTED;
            break;
        }

        case WIFIMG_PASSWORD_FAILED:
        {
            printf("Password authentication failed!\n");
            event = WIFIMG_PASSWORD_FAILED;
            break;
        }

        case WIFIMG_CONNECT_TIMEOUT:
        {
            printf("Connected timeout!\n");
            event = WIFIMG_CONNECT_TIMEOUT;
            break;
        }

        case WIFIMG_NO_NETWORK_CONNECTING:
        {
            printf("It has no wifi auto connect when wifi on!\n");
            event = WIFIMG_NO_NETWORK_CONNECTING;
            break;
        }

        case WIFIMG_CMD_OR_PARAMS_ERROR:
        {
            printf("cmd or params error!\n");
            event = WIFIMG_CMD_OR_PARAMS_ERROR;
            break;
        }

        case WIFIMG_KEY_MGMT_NOT_SUPPORT:
        {
            printf("key mgmt is not supported!\n");
            event = WIFIMG_KEY_MGMT_NOT_SUPPORT;
            break;
        }

        case WIFIMG_OPT_NO_USE_EVENT:
        {
            printf("operation no use!\n");
            event = WIFIMG_OPT_NO_USE_EVENT;
            break;
        }

        case WIFIMG_NETWORK_NOT_EXIST:
        {
            printf("network not exist!\n");
            event = WIFIMG_NETWORK_NOT_EXIST;
            break;
        }

        case WIFIMG_DEV_BUSING_EVENT:
        {
            printf("wifi device busing!\n");
            event = WIFIMG_DEV_BUSING_EVENT;
            break;
        }

        default:
        {
            printf("Other event, no care!\n");
        }
    }
}

static char * get_default_ifname(void)
{
    char * ifname = NULL;
    struct dirent *dent = NULL;

    DIR * dir = opendir(ctrl_iface_dir);

    if(!dir) 
        return NULL;

    while((dent = readdir(dir))) 
    {
        if (dent->d_type != DT_SOCK && dent->d_type != DT_UNKNOWN)
            continue;
        if (strcmp(dent->d_name, ".") == 0 || strcmp(dent->d_name, "..") == 0)
            continue;
        ifname = strdup(dent->d_name);
        break;
    }
    closedir(dir);

    return ifname;
}

static void get_wifimanager_info(char * device_name, int type, char * results)
{
    int number = 0;
    if(results && strlen(results) != 0)
    {
        if(type == 0)           // scan result
        {
            char content[64];
            char * tempstart = NULL;
            char * tempend = NULL;
            wifi_hotspot * firstnode = NULL;

            wifi_hotspot * node = malloc(sizeof(wifi_hotspot)); 
            memset(node, 0, sizeof(wifi_hotspot));
            firstnode = node;

            tempstart = results;
            tempend = strstr(tempstart, "\n");

            // if has some hot spots
            while(tempend)
            {
                tempstart = tempend + 1;

                tempend = strstr(tempstart, "\t");
                if(tempend)
                    memcpy(node->bssid, tempstart, tempend - tempstart);
                else
                    break;

                tempstart = tempend + 1;
                tempend = strstr(tempstart, "\t");
                if(tempend)
                    memcpy(node->frenquency, tempstart, tempend - tempstart);

                tempstart = tempend + 1;
                memset(content, 0, 64);
                tempend = strstr(tempstart, "\t");
                if(tempend)
                {
                    memcpy(content, tempstart, tempend - tempstart);
                    node->signal_strength = 100 + atoi(content);
                }

                tempstart = tempend + 1;
                tempend = strstr(tempstart, "\t");
                if(tempend)
                    memcpy(node->capabilities, tempstart, tempend - tempstart);

                tempstart = tempend + 1;
                tempend = strstr(tempstart, "\n");
                if(tempend)
                {
                    change_string(tempstart, tempend - tempstart, (unsigned char *)content, 64);
                    memcpy(node->ssid, content, strlen(content));
                }
                else
                {
                    change_string(tempstart, strlen(tempstart), (unsigned char *)content, 64);
                    memcpy(node->ssid, content, strlen(content));
                    number ++;
                    break;
                }

                number ++;
                node->next = malloc(sizeof(wifi_hotspot));
                node = node->next;
                memset(node, 0, sizeof(wifi_hotspot));
            }

            if(number == 0)
            {
                free(firstnode);
                firstnode = NULL;
            }

            wifiOps.report_wifi_scan_info(device_name, type, (void *)firstnode, number);
        }
        else if(type == 1)
            wifiOps.report_wifi_scan_info(device_name, type, (void *)results, 1024);
    }
}

static int open_device(const char * device_name, wifi_context ** context)
{
    wifi_context * con = NULL;
    char * ctrl_ifname = NULL;
    char results[256];
    wifi_callback callback;

    memset(results, 0, 256);
    if(device_name == NULL)
    {
        ctrl_ifname = get_default_ifname();

        if(ctrl_ifname)
        {
            sprintf(results, "%s/%s", ctrl_iface_dir, ctrl_ifname);
            free(ctrl_ifname);
        }
        else
        {
            * context = NULL;
            return ERR_OPEN_WIFI_DEVICE;
        }
    }
    else
        sprintf(results, "%s/%s", ctrl_iface_dir, device_name);

    con = malloc(sizeof(wifi_context));
    memset(con, 0, sizeof(wifi_context));
    * context = con;

    memset(&callback ,0, sizeof(callback));
    memcpy(callback.device_name, device_name, strlen(device_name));
    callback.info_callback = get_wifimanager_info;

    con->event_label = rand();
    con->p_wifi_interface = aw_wifi_on(wifi_event_handle, con->event_label, results, &callback);
    if(con->p_wifi_interface == NULL)
    {
        free(con);
        * context = NULL;
        return ERR_OPEN_WIFI_DEVICE;
    }

    while(aw_wifi_get_wifi_state() == WIFIMG_WIFI_BUSING)
    {
        printf("wifi state busing,waiting\n");
        usleep(2000000);
    }

    return ERR_NO;
}

static int close_device(wifi_context * context)
{
    int ret_code = 0;
    context->event_label++;
    ret_code = aw_wifi_off(context->p_wifi_interface);
    if(ret_code)
        return ERR_CLOSE_WIFI_DEVICE;

    if(context)
        free(context);
    return 0;
}

static int connect(wifi_context * context, const char * ssid, const char *password)
{
    int ret_code = 0;

    if((context == NULL) || (ssid == NULL) || (strlen(ssid) == 0))
        return -1;

    context->event_label++;
    ret_code = context->p_wifi_interface->connect_ap(ssid, password, context->event_label);

    return ret_code;
}

static int disconnect(wifi_context * context)
{
    int ret_code = 0;

    if(context == NULL)
        return -1;

    context->event_label++;
    ret_code = context->p_wifi_interface->disconnect_ap(context->event_label);

    while(context->p_wifi_interface->wifi_get_wifi_state() == WIFIMG_WIFI_BUSING)
    {
        printf("wifi state busing,waiting\n");
        usleep(2000000);
    }
    return ret_code;
}

static int start_scan(wifi_context * context)
{
    int ret_code = 0;

    if(context == NULL)
        return -1;

    context->event_label++;
    ret_code = context->p_wifi_interface->start_scan(context->event_label);

    return ret_code;
}

static int stop_scan(wifi_context * context)
{
    int ret_code = 0;

    if(context == NULL)
        return -1;

    return ret_code;
}

static unsigned int get_hotspots(wifi_context * context, wifi_hotspot ** hotspots)
{
    unsigned int ret_code = 0;
    int len = 4096;
    char results[4096];
    char content[64];

    memset(results, 0, 4096);
    ret_code = context->p_wifi_interface->get_scan_results(results, &len);

    if(ret_code == 0)
    {
        char * tempstart = NULL;
        char * tempend = NULL;

        wifi_hotspot * node = malloc(sizeof(wifi_hotspot)); 
        memset(node, 0, sizeof(wifi_hotspot));
        * hotspots = node;

        tempstart = results;
        tempend = strstr(tempstart, "\n");

        // if has some hot spots
        while(tempend)
        {
            tempstart = tempend + 1;

            tempend = strstr(tempstart, "\t");
            if(tempend)
                memcpy(node->bssid, tempstart, tempend - tempstart);
            else
                break;

            tempstart = tempend + 1;
            tempend = strstr(tempstart, "\t");
            if(tempend)
                memcpy(node->frenquency, tempstart, tempend - tempstart);

            tempstart = tempend + 1;
            memset(content, 0, 64);
            tempend = strstr(tempstart, "\t");
            if(tempend)
            {
                memcpy(content, tempstart, tempend - tempstart);
                node->signal_strength = 100 + atoi(content);
            }

            tempstart = tempend + 1;
            tempend = strstr(tempstart, "\t");
            if(tempend)
                memcpy(node->capabilities, tempstart, tempend - tempstart);

            tempstart = tempend + 1;
            tempend = strstr(tempstart, "\n");
            if(tempend)
            {
                change_string(tempstart, tempend - tempstart, (unsigned char *)content, 64);
                memcpy(node->ssid, content, strlen(content));
            }
            else
            {
                change_string(tempstart, strlen(tempstart), (unsigned char *)content, 64);
                memcpy(node->ssid, content, strlen(content));

                node->next = malloc(sizeof(wifi_hotspot));
                node = node->next;
                memset(node, 0, sizeof(wifi_hotspot));
                break;
            }

            node->next = malloc(sizeof(wifi_hotspot));
            node = node->next;
            memset(node, 0, sizeof(wifi_hotspot));
        }
    }
    return ret_code;
}

static int get_cur_net_info(wifi_context * context, char * reply, int reply_length)
{
    unsigned int ret_code = 0;

    if(context == NULL)
        return -1;

    context->event_label++;
    ret_code = context->p_wifi_interface->wifi_get_wifi_info(reply, reply_length);

    return ret_code;
}

static int set_scan_interval(wifi_context * context, int scan_interval)
{
    unsigned int ret_code = 0;

    if(context == NULL)
        return -1;

    ret_code = context->p_wifi_interface->set_scan_interval(scan_interval);
    return ret_code;
}


// initialize device.
hiWiFiDeviceOps * __wifi_device_ops_get(void)
{
    // initialize wifiOps 
    wifiOps.open = open_device;
    wifiOps.close = close_device;
    wifiOps.connect = connect;
    wifiOps.disconnect = disconnect;
    wifiOps.stop_scan = stop_scan;
    wifiOps.start_scan = start_scan;
    wifiOps.get_hotspots = get_hotspots;
    wifiOps.get_cur_net_info = get_cur_net_info;
    wifiOps.set_scan_interval = set_scan_interval;
    wifiOps.report_wifi_scan_info = NULL;
    return &wifiOps;
}
