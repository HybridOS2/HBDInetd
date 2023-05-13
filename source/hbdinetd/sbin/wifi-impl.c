#include <hbdbus/hbdbus.h>

#include "wifi_intf.h"
#include "inetd.h"
#include "tools.h"
#include "wifi.h"

extern const char *op_errors[];
extern hbdbus_conn * hbdbus_context_inetd;

char * wifiStartScanHotspots(hbdbus_conn* conn, const char* from_endpoint, const char* to_method, const char* method_param, int *err_code)
{
    hbdbus_json *jo = NULL;
    hbdbus_json *jo_tmp = NULL;
    const char * device_name = NULL;
    int index = -1;
    int ret_code = ERR_NO;
    char * ret_string = malloc(8192);
    WiFi_device * wifi_device = NULL;

    memset(ret_string, 0, 8192);
    sprintf(ret_string, "{\"data\":[");

    // get device array
    network_device * device = hbdbus_conn_get_user_data(conn);
    if(device == NULL)
    {
        ret_code = ERR_NONE_DEVICE_LIST;
        goto failed;
    }

    // get procedure name
    if(strncasecmp(to_method, METHOD_WIFI_START_SCAN, strlen(METHOD_WIFI_START_SCAN)))
    {
        ret_code = ERR_WRONG_PROCEDURE;
        goto failed;
    }

    // analyze json
    jo = hbdbus_json_object_from_string(method_param, strlen(method_param), 2);
    if(jo == NULL)
    {
        ret_code = ERR_WRONG_JSON;
        goto failed;
    }

    // get device name
    if(json_object_object_get_ex(jo, "device", &jo_tmp) == 0)
    {
        ret_code = ERR_WRONG_JSON;
        goto failed;
    }

    device_name = json_object_get_string(jo_tmp);
    if(device_name && strlen(device_name) == 0)
    {
        ret_code = ERR_NO_DEVICE_NAME_IN_PARAM;
        goto failed;
    }

    // device does exist?
    index = get_device_index(device, device_name);
    if(index == -1)
    {
        ret_code = ERR_NO_DEVICE_IN_SYSTEM;
        goto failed;
    }

    if(device[index].type != DEVICE_TYPE_WIFI)
    {
        ret_code = ERR_NOT_WIFI_DEVICE;
        goto failed;
    }
        
    // whether library has been loaded
    if(device[index].lib_handle == NULL)
    {
        ret_code = ERR_LOAD_LIBRARY;
        goto failed;
    }

    wifi_device = (WiFi_device *)device[index].device;
    if(wifi_device->context == NULL)
    {
        ret_code = ERR_DEVICE_NOT_OPENNED;
        goto failed;
    }

    if((device[index].status == DEVICE_STATUS_DOWN) || (device[index].status == DEVICE_STATUS_UNCERTAIN))
    {
        ret_code = ERR_OPEN_WIFI_DEVICE;
        if(ifconfig_helper(device_name, 1))
            goto failed;
    }

    ret_code = wifi_device->wifi_device_Ops->start_scan(wifi_device->context);

    pthread_mutex_lock(&(wifi_device->list_mutex));
    wifi_hotspot * node = wifi_device->first_hotspot;
    while(node)
    {
        if(node != wifi_device->first_hotspot)
            sprintf(ret_string + strlen(ret_string), ",");
        sprintf(ret_string + strlen(ret_string), 
                "{"
                "\"bssid\":\"%s\","
                "\"ssid\":\"%s\","
                "\"frequency\":\"%s\","
                "\"capabilities\":\"%s\","
                "\"signalStrength\":%d,"
                "\"isConnected\":%s"
                "}",
                node->bssid, node->ssid, node->frenquency, node->capabilities, node->signal_strength, node->isConnect ? "true": "false");

        node = node->next;
    }
    pthread_mutex_unlock(&(wifi_device->list_mutex));

failed:
    if(jo)
        json_object_put (jo);

    sprintf(ret_string + strlen(ret_string), "],\"errCode\":%d, \"errMsg\":\"%s\"}", ret_code, op_errors[-1 * ret_code]);
    return ret_string;

}

char * wifiStopScanHotspots(hbdbus_conn* conn, const char* from_endpoint, const char* to_method, const char* method_param, int *err_code)
{
    hbdbus_json *jo = NULL;
    hbdbus_json *jo_tmp = NULL;
    const char * device_name = NULL;
    int index = -1;
    int ret_code = ERR_NO;
    char * ret_string = malloc(4096);
    WiFi_device * wifi_device = NULL;

    // get device array
    network_device * device = hbdbus_conn_get_user_data(conn);
    if(device == NULL)
    {
        ret_code = ERR_NONE_DEVICE_LIST;
        goto failed;
    }

    // get procedure name
    if(strncasecmp(to_method, METHOD_WIFI_STOP_SCAN, strlen(METHOD_WIFI_STOP_SCAN)))
    {
        ret_code = ERR_WRONG_PROCEDURE;
        goto failed;
    }

    // analyze json
    jo = hbdbus_json_object_from_string(method_param, strlen(method_param), 2);
    if(jo == NULL)
    {
        ret_code = ERR_WRONG_JSON;
        goto failed;
    }

    // get device name
    if(json_object_object_get_ex(jo, "device", &jo_tmp) == 0)
    {
        ret_code = ERR_WRONG_JSON;
        goto failed;
    }

    device_name = json_object_get_string(jo_tmp);
    if(device_name && strlen(device_name) == 0)
    {
        ret_code = ERR_NO_DEVICE_NAME_IN_PARAM;
        goto failed;
    }

    // device does exist?
    index = get_device_index(device, device_name);
    if(index == -1)
    {
        ret_code = ERR_NO_DEVICE_IN_SYSTEM;
        goto failed;
    }

    if(device[index].type != DEVICE_TYPE_WIFI)
    {
        ret_code = ERR_NOT_WIFI_DEVICE;
        goto failed;
    }
        
    if(device[index].lib_handle == NULL)
    {
        ret_code = ERR_LOAD_LIBRARY;
        goto failed;
    }

    wifi_device = (WiFi_device *)device[index].device;
    if(wifi_device->context == NULL)
    {
        ret_code = ERR_DEVICE_NOT_OPENNED;
        goto failed;
    }

    if((device[index].status == DEVICE_STATUS_DOWN) || (device[index].status == DEVICE_STATUS_UNCERTAIN))
    {
        ret_code = ERR_OPEN_WIFI_DEVICE;
        if(ifconfig_helper(device_name, 1))
            goto failed;
    }

    ret_code = wifi_device->wifi_device_Ops->stop_scan(wifi_device->context);

failed:
    if(jo)
        json_object_put (jo);

    memset(ret_string, 0, 4096);
    sprintf(ret_string, "{\"errCode\":%d, \"errMsg\":\"%s\"}", ret_code, op_errors[-1 * ret_code]);
    return ret_string;
}

char * wifiConnect(hbdbus_conn* conn, const char* from_endpoint, const char* to_method, const char* method_param, int *err_code)
{
    hbdbus_json *jo = NULL;
    hbdbus_json *jo_tmp = NULL;
    const char * device_name = NULL;
    const char * ssid = NULL;
    const char * password = NULL;
    int index = -1;
    int ret_code = ERR_NO;
    char * ret_string = malloc(4096);
    WiFi_device * wifi_device = NULL;

    // get device array
    network_device * device = hbdbus_conn_get_user_data(conn);
    if(device == NULL)
    {
        ret_code = ERR_NONE_DEVICE_LIST;
        goto failed;
    }

    // get procedure name
    if(strncasecmp(to_method, METHOD_WIFI_CONNECT_AP, strlen(METHOD_WIFI_CONNECT_AP)))
    {
        ret_code = ERR_WRONG_PROCEDURE;
        goto failed;
    }

    // analyze json
    jo = hbdbus_json_object_from_string(method_param, strlen(method_param), 2);
    if(jo == NULL)
    {
        ret_code = ERR_WRONG_JSON;
        goto failed;
    }

    // get device name
    if(json_object_object_get_ex(jo, "device", &jo_tmp) == 0)
    {
        ret_code = ERR_WRONG_JSON;
        goto failed;
    }

    device_name = json_object_get_string(jo_tmp);
    if(device_name && strlen(device_name) == 0)
    {
        ret_code = ERR_NO_DEVICE_NAME_IN_PARAM;
        goto failed;
    }

    // device does exist?
    index = get_device_index(device, device_name);
    if(index == -1)
    {
        ret_code = ERR_NO_DEVICE_IN_SYSTEM;
        goto failed;
    }

    if(device[index].type != DEVICE_TYPE_WIFI)
    {
        ret_code = ERR_NOT_WIFI_DEVICE;
        goto failed;
    }
    
    // get WiFi ssid 
    if(json_object_object_get_ex(jo, "ssid", &jo_tmp) == 0)
    {
        ret_code = ERR_WRONG_JSON;
        goto failed;
    }

    ssid = json_object_get_string(jo_tmp);
    if(ssid && strlen(ssid) == 0)
    {
        ret_code = ERR_NO_DEVICE_NAME_IN_PARAM;
        goto failed;
    }

    // get WiFi password 
    if(json_object_object_get_ex(jo, "password", &jo_tmp) == 0)
    {
        ret_code = ERR_WRONG_JSON;
        goto failed;
    }

    password = json_object_get_string(jo_tmp);
    if(password && strlen(password) == 0)
    {
        ret_code = ERR_NO_DEVICE_NAME_IN_PARAM;
        goto failed;
    }

    if(device[index].lib_handle == NULL)
    {
        ret_code = ERR_LOAD_LIBRARY;
        goto failed;
    }

    wifi_device = (WiFi_device *)device[index].device;
    if(wifi_device->context == NULL)
    {
        ret_code = ERR_DEVICE_NOT_OPENNED;
        goto failed;
    }

    if((device[index].status == DEVICE_STATUS_DOWN) || (device[index].status == DEVICE_STATUS_UNCERTAIN))
    {
        ret_code = ERR_OPEN_WIFI_DEVICE;
        if(ifconfig_helper(device_name, 1))
            goto failed;
    }

    ret_code = wifi_device->wifi_device_Ops->connect(wifi_device->context, ssid, password);

    if(ret_code == 0)
    {
        char reply[512];
        int reply_length = 512;
        int i = 0;

        memset(wifi_device->bssid, 0, HOTSPOT_STRING_LENGTH);

        ret_code = ERR_LIBRARY_OPERATION;
        while(ret_code)
        {
            usleep(100000);

            i ++;
            if(i > 200)
                goto failed;

            memset(reply, 0, 512);
            ret_code = wifi_device->wifi_device_Ops->get_cur_net_info(wifi_device->context, reply, reply_length);
        }

        if(ret_code == 0)
        {
            char * tempstart = NULL;
            char * tempend = NULL;
            char content[64];

            memset(content, 0, 64);
            tempstart = strstr(reply, "wpa_state=");
            if(tempstart)
            {
                tempstart += strlen("wpa_state=");
                tempend = strstr(tempstart, "\n");
                if(tempend)
                {
                    memcpy(content, tempstart, tempend - tempstart);
                    if(strncasecmp(content, "COMPLETED", strlen("COMPLETED")) == 0)
                    {
                        device[index].status = DEVICE_STATUS_RUNNING;
                        
                        // bssid
                        tempstart = strstr(reply, "bssid=");
                        if(tempstart)
                        {
                            tempstart += strlen("bssid=");
                            tempend = strstr(tempstart, "\n");
                            if(tempend)
                                memcpy(wifi_device->bssid, tempstart, tempend - tempstart);
                        }
                    }
                }
            }

            wifi_hotspot * node = wifi_device->first_hotspot;

            pthread_mutex_lock(&(wifi_device->list_mutex));
            while(node)
            {
                if(strcmp((char *)wifi_device->bssid, (char *)node->bssid) == 0)
                {
                    wifi_device->signal = node->signal_strength;
                    break;
                }
                node = node->next;
            }
            pthread_mutex_unlock(&(wifi_device->list_mutex));
        }
    }
failed:
    if(jo)
        json_object_put (jo);

    memset(ret_string, 0, 4096);
    sprintf(ret_string, "{\"errCode\":%d, \"errMsg\":\"%s\"}", ret_code, op_errors[-1 * ret_code]);
    return ret_string;
}

char * wifiDisconnect(hbdbus_conn* conn, const char* from_endpoint, const char* to_method, const char* method_param, int *err_code)
{
    hbdbus_json *jo = NULL;
    hbdbus_json *jo_tmp = NULL;
    const char * device_name = NULL;
    int index = -1;
    int ret_code = ERR_NO;
    char * ret_string = malloc(4096);
    WiFi_device * wifi_device = NULL;

    // get device array
    network_device * device = hbdbus_conn_get_user_data(conn);
    if(device == NULL)
    {
        ret_code = ERR_NONE_DEVICE_LIST;
        goto failed;
    }

    // get procedure name
    if(strncasecmp(to_method, METHOD_WIFI_DISCONNECT_AP, strlen(METHOD_WIFI_CONNECT_AP)))
    {
        ret_code = ERR_WRONG_PROCEDURE;
        goto failed;
    }

    // analyze json
    jo = hbdbus_json_object_from_string(method_param, strlen(method_param), 2);
    if(jo == NULL)
    {
        ret_code = ERR_WRONG_JSON;
        goto failed;
    }

    // get device name
    if(json_object_object_get_ex(jo, "device", &jo_tmp) == 0)
    {
        ret_code = ERR_WRONG_JSON;
        goto failed;
    }

    device_name = json_object_get_string(jo_tmp);
    if(device_name && strlen(device_name) == 0)
    {
        ret_code = ERR_NO_DEVICE_NAME_IN_PARAM;
        goto failed;
    }

    // device does exist?
    index = get_device_index(device, device_name);
    if(index == -1)
    {
        ret_code = ERR_NO_DEVICE_IN_SYSTEM;
        goto failed;
    }

    if(device[index].type != DEVICE_TYPE_WIFI)
    {
        ret_code = ERR_NOT_WIFI_DEVICE;
        goto failed;
    }
    
    if(device[index].lib_handle == NULL)
    {
        ret_code = ERR_LOAD_LIBRARY;
        goto failed;
    }

    wifi_device = (WiFi_device *)device[index].device;
    if(wifi_device->context == NULL)
    {
        ret_code = ERR_DEVICE_NOT_OPENNED;
        goto failed;
    }

    wifi_device->wifi_device_Ops->disconnect(wifi_device->context);

    memset(wifi_device->bssid, 0, HOTSPOT_STRING_LENGTH);
    wifi_device->signal = 0;

    // remove hot spots list
    wifi_hotspot * node = NULL;
    wifi_hotspot * tempnode = NULL;

    pthread_mutex_lock(&(wifi_device->list_mutex));
    node = wifi_device->first_hotspot;
    while(node)
    {
        tempnode = node->next;
        free(node);
        node = tempnode;
    }
    wifi_device->first_hotspot = NULL;
    pthread_mutex_unlock(&(wifi_device->list_mutex));

failed:
    if(jo)
        json_object_put (jo);

    sprintf(ret_string, "{\"errCode\":%d, \"errMsg\":\"%s\"}", ret_code, op_errors[-1 * ret_code]);
    return ret_string;
}

char * wifiGetNetworkInfo(hbdbus_conn* conn, const char* from_endpoint, const char* to_method, const char* method_param, int *err_code)
{
    hbdbus_json *jo = NULL;
    hbdbus_json *jo_tmp = NULL;
    const char * device_name = NULL;
    char reply[512];
    int reply_length = 512;
    int index = -1;
    int ret_code = ERR_NO;
    char * ret_string = malloc(4096);
    WiFi_device * wifi_device = NULL;

    memset(ret_string, 0, 4096);
    sprintf(ret_string, "{\"data\":{");

    // get device array
    network_device * device = hbdbus_conn_get_user_data(conn);
    if(device == NULL)
    {
        ret_code = ERR_NONE_DEVICE_LIST;
        goto failed;
    }

    // get procedure name
    if(strncasecmp(to_method, METHOD_WIFI_GET_NETWORK_INFO, strlen(METHOD_WIFI_GET_NETWORK_INFO)))
    {
        ret_code = ERR_WRONG_PROCEDURE;
        goto failed;
    }

    // analyze json
    jo = hbdbus_json_object_from_string(method_param, strlen(method_param), 2);
    if(jo == NULL)
    {
        ret_code = ERR_WRONG_JSON;
        goto failed;
    }

    // get device name
    if(json_object_object_get_ex(jo, "device", &jo_tmp) == 0)
    {
        ret_code = ERR_WRONG_JSON;
        goto failed;
    }

    device_name = json_object_get_string(jo_tmp);
    if(device_name && strlen(device_name) == 0)
    {
        ret_code = ERR_NO_DEVICE_NAME_IN_PARAM;
        goto failed;
    }

    // device does exist?
    index = get_device_index(device, device_name);
    if(index == -1)
    {
        ret_code = ERR_NO_DEVICE_IN_SYSTEM;
        goto failed;
    }

    if(device[index].type != DEVICE_TYPE_WIFI)
    {
        ret_code = ERR_NOT_WIFI_DEVICE;
        goto failed;
    }
    
    if(device[index].lib_handle == NULL)
    {
        ret_code = ERR_LOAD_LIBRARY;
        goto failed;
    }

    wifi_device = (WiFi_device *)device[index].device;
    if(wifi_device->context == NULL)
    {
        ret_code = ERR_DEVICE_NOT_OPENNED;
        goto failed;
    }

    ret_code = wifi_device->wifi_device_Ops->get_cur_net_info(wifi_device->context, reply, reply_length);


    if(ret_code == 0)
    {
        char * tempstart = NULL;
        char * tempend = NULL;
        char content[64];

        memset(content, 0, 64);
        tempstart = strstr(reply, "wpa_state=");
        if(tempstart)
        {
            tempstart += strlen("wpa_state=");
            tempend = strstr(tempstart, "\n");
            if(tempend)
            {
                memcpy(content, tempstart, tempend - tempstart);
                if(strncasecmp(content, "COMPLETED", strlen("COMPLETED")))
                {
                    ret_code = ERR_DEVICE_NOT_CONNECT;
                    goto failed;
                }
            }
            else
            {
                ret_code = ERR_DEVICE_NOT_CONNECT;
                goto failed;
            }
        }
        else
        {
            ret_code = ERR_DEVICE_NOT_CONNECT;
            goto failed;
        }
        
        device[index].status = DEVICE_STATUS_RUNNING;

        // device name
        sprintf(ret_string + strlen(ret_string), "\"device\":\"%s\",", device_name);

        // bssid
        memset(content, 0, 64);
        tempstart = strstr(reply, "bssid=");
        if(tempstart)
        {
            tempstart += strlen("bssid=");
            tempend = strstr(tempstart, "\n");
            if(tempend)
                memcpy(content, tempstart, tempend - tempstart);
        }
        sprintf(ret_string + strlen(ret_string), "\"bssid\":\"%s\",", content);
        memset(wifi_device->bssid, 0, HOTSPOT_STRING_LENGTH);
        sprintf(wifi_device->bssid, "%s", content);

        // frenquency 
        memset(content, 0, 64);
        tempstart = strstr(tempend, "freq=");
        if(tempstart)
        {
            tempstart += strlen("freq=");
            tempend = strstr(tempstart, "\n");
            if(tempend)
                memcpy(content, tempstart, tempend - tempstart);
        }
        sprintf(ret_string + strlen(ret_string), "\"frenquency\":\"%s MHz\",", content);

        // ssid
        memset(content, 0, 64);
        tempstart = strstr(tempend, "ssid=");
        if(tempstart)
        {
            tempstart += strlen("ssid=");
            tempend = strstr(tempstart, "\n");
            if(tempend)
                memcpy(content, tempstart, tempend - tempstart);
        }
        sprintf(ret_string + strlen(ret_string), "\"ssid\":\"%s\",", content);


        // encryptionType
        memset(content, 0, 64);
        tempstart = strstr(tempend, "key_mgmt=");
        if(tempstart)
        {
            tempstart += strlen("key_mgmt=");
            tempend = strstr(tempstart, "\n");
            if(tempend)
                memcpy(content, tempstart, tempend - tempstart);
        }
        sprintf(ret_string + strlen(ret_string), "\"encryptionType\":\"%s\",", content);

        // ip
        memset(content, 0, 64);
        tempstart = strstr(tempend, "ip_address=");
        if(tempstart)
        {
            tempstart += strlen("ip_address=");
            tempend = strstr(tempstart, "\n");
            if(tempend)
                memcpy(content, tempstart, tempend - tempstart);
        }
        sprintf(ret_string + strlen(ret_string), "\"ip\":\"%s\",", content);
        memset(device[index].ip, 0, NETWORK_ADDRESS_LENGTH);
        sprintf(device[index].ip, "%s", content);

        // mac
        memset(content, 0, 64);
        tempstart = strstr(tempend, "address=");
        if(tempstart)
        {
            tempstart += strlen("address=");
            tempend = strstr(tempstart, "\n");
            if(tempend)
                memcpy(content, tempstart, tempend - tempstart);
        }
        sprintf(ret_string + strlen(ret_string), "\"mac\":\"%s\",", content);
        memset(device[index].mac, 0, NETWORK_ADDRESS_LENGTH);
        sprintf(device[index].mac, "%s", content);

        // speed
        sprintf(ret_string + strlen(ret_string), "\"speed\":\"%d Mbps\",", device[index].speed);

        // gate way

        // singal
        sprintf(ret_string + strlen(ret_string), "\"signalStrength\":%d", wifi_device->signal);
    }

failed:
    if(jo)
        json_object_put (jo);

    sprintf(ret_string + strlen(ret_string), "},");
    sprintf(ret_string + strlen(ret_string), "\"errCode\":%d, \"errMsg\":\"%s\"}", ret_code, op_errors[-1 * ret_code]);

    return ret_string;
}

void report_wifi_scan_info(char * device_name, int type, void * results, int number)
{
    wifi_hotspot * node = NULL;
    wifi_hotspot * tempnode = NULL;

    network_device * device_array = NULL; 
    int index = 0;
    WiFi_device * wifi_device = NULL;

    if(hbdbus_context_inetd == NULL)
        return;
    device_array = hbdbus_conn_get_user_data(hbdbus_context_inetd);
    if(device_array == NULL)
        return;

    index = get_device_index(device_array, device_name);
    if(index == -1)
        return;

    if(device_array[index].type != DEVICE_TYPE_WIFI)
        return;

    if(device_array[index].lib_handle == NULL)
        return;

    wifi_device = (WiFi_device *)(device_array[index].device);
    if(wifi_device == NULL)
        return;

    if(type == 0)
    {
        wifi_hotspot * hotspots = results;
        wifi_hotspot nodecopy;
        wifi_hotspot * nodecopynext = NULL;

        if(hotspots == NULL)
            return;

        // according to signal strength, order the list
        if(number > 1)
        {
            int i = 1;
            int j = i + 1;
            node = hotspots;

            for(i = 1; i < number - 1; i++)
            {
                node = node->next;
                tempnode = node->next;
                for(j = i + 1; j < number; j++)
                {
                    if(node->signal_strength < tempnode->signal_strength)
                    {
                        nodecopynext = node->next;
                        node->next = tempnode->next;
                        tempnode->next = nodecopynext;

                        memcpy(&nodecopy, node, sizeof(wifi_hotspot));
                        memcpy(node, tempnode, sizeof(wifi_hotspot));
                        memcpy(tempnode, &nodecopy, sizeof(wifi_hotspot));
                    }
                    tempnode = tempnode->next;
                }
            }
        }

        // the connected ssid is the first
        if(strlen(wifi_device->bssid))
        {
            node = hotspots;
            while(node)
            {
                if(strcmp((char *)wifi_device->bssid, (char *)node->bssid) == 0)
                {
                    if(node != hotspots)
                    {
                        nodecopynext = node->next;
                        node->next = hotspots->next;
                        hotspots->next = nodecopynext;

                        memcpy(&nodecopy, node, sizeof(wifi_hotspot));
                        memcpy(node, hotspots, sizeof(wifi_hotspot));
                        memcpy(hotspots, &nodecopy, sizeof(wifi_hotspot));
                        break;
                    }
                }
                node = node->next;
            }
        }

        // send the message
        char * signal = malloc(4096);
        char * remove = malloc(4096);
        char * added = malloc(8192);
        char * message = malloc(8192);
        bool bsignal = false;
        bool bremove = false;
        bool bnew = false;
        bool changedssid = false;
        bool changedsignal = false;
        bool changedcapabilities = false;
        int i = 0;
        wifi_hotspot * host = wifi_device->first_hotspot;

        // send WIFISIGNALSTRENGTHCHANGED message
        if(hotspots && wifi_device->bssid[0] && strcmp((char *)wifi_device->bssid, (char *)hotspots->bssid) == 0)
        {
            wifi_device->signal = hotspots->signal_strength;
            memset(signal, 0, 4096);
            sprintf(signal, "{\"bssid\":\"%s\", \"ssid\":\"%s\", \"signalStrength\":%d}", hotspots->bssid, hotspots->ssid, hotspots->signal_strength);
            hbdbus_fire_event(hbdbus_context_inetd, WIFISIGNALSTRENGTHCHANGED, signal);
        }

        // if scan ap, send WIFIHOTSPOTSCHANGED message
        memset(signal, 0, 4096);
        sprintf(signal, "\"changed\":[");

        memset(remove, 0, 4096);
        sprintf(remove, "\"missed\":[");

        memset(added, 0, 8192);
        sprintf(added, "\"found\":[");

        if(host == NULL)            // all is new ap
        {
            node = hotspots;
            for(i = 0; i < number; i++)
            {
                if(node != hotspots)
                    sprintf(added + strlen(added), ",");

                sprintf(added + strlen(added), 
                        "{"
                        "\"bssid\":\"%s\","
                        "\"ssid\":\"%s\","
                        "\"capabilities\":\"%s\","
                        "\"signalStrength\":%d"
                        "}",
                        node->bssid, node->ssid, node->capabilities, node->signal_strength);
                node = node->next;
            }
        }
        else
        {
            while(host)
            {
                node = hotspots;
                i = 0;
                while(node)
                {
                    if(strcmp((char *)host->bssid, (char *)node->bssid) == 0)
                    {
                        changedssid = false;
                        changedsignal = false;
                        changedcapabilities = false;

                        // signal
                        if(host->signal_strength != node->signal_strength)
                            changedsignal = true;
                        if(strcmp((char *)host->ssid, (char *)node->ssid))
                            changedssid = true;
                        if(strcmp((char *)host->capabilities, (char *)node->capabilities))
                            changedcapabilities = true;

                        if(changedssid || changedsignal || changedcapabilities)
                        {
                            if(bsignal)
                                sprintf(signal + strlen(signal), ",");
                            bsignal = true;

                            sprintf(signal + strlen(signal), 
                                    "{"
                                        "\"bssid\":\"%s\"",
                                    node->bssid);

                            if(changedsignal)
                                    sprintf(signal + strlen(signal), 
                                        ","
                                        "\"signalStrength\":%d",
                                        node->signal_strength);

                            if(changedssid)
                                    sprintf(signal + strlen(signal), 
                                        ","
                                        "\"ssid\":\"%s\"",
                                        node->ssid);

                            if(changedcapabilities)
                                    sprintf(signal + strlen(signal), 
                                        ","
                                        "\"capabilities\":\"%s\"",
                                        node->capabilities);
                            sprintf(signal + strlen(signal), "}");
                        }

                        i = 1;                      // old ap is found in new ap list
                        node->isConnect = true;     // flag to indicate: it is not new hotspot 
                        break;
                    }
                    node = node->next;
                }

                if(i == 0)          // do not find in orignal list, it is removed
                {
                    if(bremove)
                        sprintf(remove + strlen(remove), ",");
                    bremove = true;
                    sprintf(remove + strlen(remove), 
                            "{"
                            "\"bssid\":\"%s\""
                            "}",
                            host->bssid);
                }
                host = host->next;
            }

            node = hotspots;
            host = wifi_device->first_hotspot;

            while(node)
            {
                if(!(node->isConnect))         // have been checked
                {
                    if(bnew)
                        sprintf(added + strlen(added), ",");
                    bnew = true;
                    sprintf(added + strlen(added), 
                            "{"
                            "\"bssid\":\"%s\","
                            "\"ssid\":\"%s\","
                            "\"capabilities\":\"%s\","
                            "\"signalStrength\":%d"
                            "}",
                            node->bssid, node->ssid, node->capabilities, node->signal_strength);
                }
                node->isConnect = false;
                node = node->next;
            }
        }

        memset(message, 0, 8192);
        sprintf(message, "{%s], %s], %s]}", added, remove, signal);
        hbdbus_fire_event(hbdbus_context_inetd, WIFIHOTSPOTSCHANGED, message);

        free(signal);
        free(remove);
        free(added);
        free(message);

        if(hotspots && wifi_device->bssid[0] && strcmp((char *)wifi_device->bssid, (char *)hotspots->bssid) == 0)
            hotspots->isConnect = true;;

        // set hotspots list
        pthread_mutex_lock(&(wifi_device->list_mutex));
        node = wifi_device->first_hotspot;
        while(node)
        {
            tempnode = node->next;
            free(node);
            node = tempnode;
        }
        wifi_device->first_hotspot = hotspots;
        pthread_mutex_unlock(&(wifi_device->list_mutex));
    }
}

void wifi_register(hbdbus_conn * hbdbus_context_inetd)
{
    int ret_code = 0;

    ret_code = hbdbus_register_procedure(hbdbus_context_inetd, METHOD_WIFI_START_SCAN, NULL, NULL, wifiStartScanHotspots);
    if(ret_code)
    {
        fprintf(stderr, "WIFI DAEMON: Error for register procedure %s, %s.\n", METHOD_WIFI_START_SCAN, hbdbus_get_err_message(ret_code));
        return;
    }

    ret_code = hbdbus_register_procedure(hbdbus_context_inetd, METHOD_WIFI_STOP_SCAN, NULL, NULL, wifiStopScanHotspots);
    if(ret_code)
    {
        fprintf(stderr, "WIFI DAEMON: Error for register procedure %s, %s.\n", METHOD_WIFI_STOP_SCAN, hbdbus_get_err_message(ret_code));
        return;
    }

    ret_code = hbdbus_register_procedure(hbdbus_context_inetd, METHOD_WIFI_CONNECT_AP, NULL, NULL, wifiConnect);
    if(ret_code)
    {
        fprintf(stderr, "WIFI DAEMON: Error for register procedure %s, %s.\n", METHOD_WIFI_CONNECT_AP, hbdbus_get_err_message(ret_code));
        return;
    }

    ret_code = hbdbus_register_procedure(hbdbus_context_inetd, METHOD_WIFI_DISCONNECT_AP, NULL, NULL, wifiDisconnect);
    if(ret_code)
    {
        fprintf(stderr, "WIFI DAEMON: Error for register procedure %s, %s.\n", METHOD_WIFI_DISCONNECT_AP, hbdbus_get_err_message(ret_code));
        return;
    }

    ret_code = hbdbus_register_procedure(hbdbus_context_inetd, METHOD_WIFI_GET_NETWORK_INFO, NULL, NULL, wifiGetNetworkInfo);
    if(ret_code)
    {
        fprintf(stderr, "WIFI DAEMON: Error for register procedure %s, %s.\n", METHOD_WIFI_GET_NETWORK_INFO, hbdbus_get_err_message(ret_code));
        return;
    }

    ret_code = hbdbus_register_event(hbdbus_context_inetd, WIFIHOTSPOTSCHANGED, NULL, NULL);
    if(ret_code)
    {
        fprintf(stderr, "WIFI DAEMON: Error for register event %s, %s.\n", WIFIHOTSPOTSCHANGED, hbdbus_get_err_message(ret_code));
        return;
    }

    ret_code = hbdbus_register_event(hbdbus_context_inetd, WIFISIGNALSTRENGTHCHANGED, NULL, NULL);
    if(ret_code)
    {
        fprintf(stderr, "WIFI DAEMON: Error for register event %s, %s.\n", WIFISIGNALSTRENGTHCHANGED, hbdbus_get_err_message(ret_code));
        return;
    }
}

void wifi_revoke(hbdbus_conn * hbdbus_context_inetd)
{
    hbdbus_revoke_event(hbdbus_context_inetd, WIFISIGNALSTRENGTHCHANGED);
    hbdbus_revoke_event(hbdbus_context_inetd, WIFIHOTSPOTSCHANGED);

    hbdbus_revoke_procedure(hbdbus_context_inetd, METHOD_WIFI_START_SCAN);
    hbdbus_revoke_procedure(hbdbus_context_inetd, METHOD_WIFI_STOP_SCAN);
    hbdbus_revoke_procedure(hbdbus_context_inetd, METHOD_WIFI_CONNECT_AP);
    hbdbus_revoke_procedure(hbdbus_context_inetd, METHOD_WIFI_DISCONNECT_AP);
    hbdbus_revoke_procedure(hbdbus_context_inetd, METHOD_WIFI_GET_NETWORK_INFO);
}

