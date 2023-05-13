#include <hbdbus.h>

#include "wifi_intf.h"
#include "inetd.h"
#include "tools.h"
#include "common.h"

const char *op_errors[] = {
    "success",                                  // ERR_NO
    "an error ocures in library operation.",    // ERR_LIBRARY_OPERATION
    "can not get devices list.",                // ERR_NONE_DEVICE_LIST
    "wrong procedure name.",                    // ERR_WRONG_PROCEDURE
    "wrong Json format.",                       // ERR_WRONG_JSON
    "can not find device name in param.",       // ERR_NO_DEVICE_NAME_IN_PARAM
    "can not find device in system.",           // ERR_NO_DEVICE_IN_SYSTEM
    "invalid network device type.",             // ERR_DEVICE_TYPE
    "some error in load library.",              // ERR_LOAD_LIBRARY
    "device is not WiFi device.",               // ERR_NOT_WIFI_DEVICE 
    "device has not openned.",                  // ERR_DEVICE_NOT_OPENNED 
    "an error ocurs in open wifi device.",      // ERR_OPEN_WIFI_DEVICE
    "an error ocurs in close wifi device.",     // ERR_CLOSE_WIFI_DEVICE
    "an error ocurs in open ethernet device.",  // ERR_OPEN_ETHERNET_DEVICE
    "an error ocurs in close ethernet device.", // ERR_CLOSE_ETHERNET_DEVICE
    "an error ocurs in open mobile device.",    // ERR_OPEN_MOBILE_DEVICE
    "an error ocurs in close mobile device.",   // ERR_CLOSE_MOBILE_DEVICE
    "device does not connect any network.",     // ERR_DEVICE_NOT_CONNECT
    "device is disalbe in library.",            // ERR_LIB_DEVICE_DISABLE
    "invalid ssid in library.",                 // ERR_LIB_INVALID_SSID
    "invalid password in library.",             // ERR_LIB_INVALID_PASSWORD
    "device is busy in library.",               // ERR_LIB_DEVICE_BUSY
    "the network is not existence in library.", // ERR_LIB_NET_EXISTENCE
    "an error in adding network in library.",   // ERR_LIB_ADD_NETWORK
    "an error in setting network in library.",  // ERR_LIB_SET_NETWORK
    "an error in selecting network in library.",// ERR_LIB_SELECT_NETWORK
    "an error in enable network in library.",   // ERR_LIB_ENABLE_NETWORK
    "an error in reconnecting net in lib.",     // ERR_LIB_RECONNECT_NETWORK
    "WRONG PASSWORD!"                           // ERR_LIB_WRONG_PASSWORD
};

char * openDevice(hbdbus_conn* conn, const char* from_endpoint, const char* to_method, const char* method_param, int *err_code)
{
    hbdbus_json *jo = NULL;
    hbdbus_json *jo_tmp = NULL;
    const char * device_name = NULL;
    int index = -1;
    int ret_code = ERR_NO;
    char * ret_string = malloc(256);
    WiFi_device * wifi_device = NULL;

    // get device array
    network_device * device = hbdbus_conn_get_user_data(conn);
    if(device == NULL)
    {
        ret_code = ERR_NONE_DEVICE_LIST;
        goto failed;
    }

    // get procedure name
    if(strncasecmp(to_method, METHOD_NET_OPEN_DEVICE, strlen(METHOD_NET_OPEN_DEVICE)))
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

    // whether openned
    if(device[index].lib_handle)
    {
        ret_code = ERR_NO;
        goto failed;
    }

    // load the library
    if(load_device_library(&device[index]))
    {
        ret_code = ERR_LOAD_LIBRARY;
        goto failed;
    }

    get_if_info(&device[index]);

    if(device[index].type == DEVICE_TYPE_WIFI)
    {
        int loop = 0;
        wifi_device = (WiFi_device *)device[index].device;

        // if the interface is down, up it now
        if((device[index].status == DEVICE_STATUS_DOWN) || (device[index].status == DEVICE_STATUS_UNCERTAIN))
        {
            system("rfkill unblock wifi");
            ret_code = ERR_OPEN_WIFI_DEVICE;
            if(ifconfig_helper(device_name, 1))
                goto failed;
        }

        get_if_info(&device[index]);
        while((device[index].status != DEVICE_STATUS_UP) && (device[index].status != DEVICE_STATUS_RUNNING))
        {
            if(loop > 200)
                break;
            usleep(10000);
            get_if_info(&device[index]);
        }
    
        if((device[index].status != DEVICE_STATUS_UP) && (device[index].status != DEVICE_STATUS_RUNNING))
        {
            ret_code = ERR_OPEN_WIFI_DEVICE;
            goto failed;
        }

        // if the device is not openned
        ret_code = ERR_NO;
        ret_code = wifi_device->wifi_device_Ops->open(device_name, &(wifi_device->context));
        if(ret_code != 0)
            goto failed;

        wifi_device->wifi_device_Ops->set_scan_interval(wifi_device->context, wifi_device->scan_time);
    }
    else if(device[index].type == DEVICE_TYPE_ETHERNET)
    {
        ret_code = ERR_OPEN_ETHERNET_DEVICE;
        if(ifconfig_helper(device_name, 1))
            goto failed;
        ret_code = ERR_NO;
    }
    else if(device[index].type == DEVICE_TYPE_MOBILE)
    {
        ret_code = ERR_OPEN_MOBILE_DEVICE;
        if(ifconfig_helper(device_name, 1))
            goto failed;
        ret_code = ERR_NO;
    }
    else
        ret_code = ERR_DEVICE_TYPE; 

failed:
    if(jo)
        json_object_put (jo);

    memset(ret_string, 0, 256);
    sprintf(ret_string, "{\"errCode\":%d, \"errMsg\":\"%s\"}", ret_code, op_errors[-1 * ret_code]);
    return ret_string;

}

char * closeDevice(hbdbus_conn* conn, const char* from_endpoint, const char* to_method, const char* method_param, int *err_code)
{
    hbdbus_json *jo = NULL;
    hbdbus_json *jo_tmp = NULL;
    const char * device_name = NULL;
    int index = -1;
    int ret_code = 0;
    char * ret_string = malloc(256);
    WiFi_device * wifi_device = NULL;

    network_device * device = hbdbus_conn_get_user_data(conn);
    if(device == NULL)
    {
        ret_code = ERR_NONE_DEVICE_LIST;
        goto failed;
    }

    if(strncasecmp(to_method, METHOD_NET_CLOSE_DEVICE, strlen(METHOD_NET_CLOSE_DEVICE)))
    {
        ret_code = ERR_WRONG_PROCEDURE;
        goto failed;
    }

    jo = hbdbus_json_object_from_string(method_param, strlen(method_param), 2);
    if(jo == NULL)
    {
        ret_code = ERR_WRONG_JSON;
        goto failed;
    }

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

    index = get_device_index(device, device_name);
    if(index == -1)
    {
        ret_code = ERR_NO_DEVICE_IN_SYSTEM;
        goto failed;
    }

    // whether closed 
    if(device[index].lib_handle == NULL)
    {
        ret_code = ERR_NO;
        goto failed;
    }

    if(device[index].type == DEVICE_TYPE_WIFI)
    {
        // whether library has been loaded
        wifi_device = (WiFi_device *)device[index].device;
        if(wifi_device == NULL)
        {
            ret_code = ERR_LOAD_LIBRARY;
            goto failed;
        }
        else
        {
            // if the device is openned
            wifi_device->wifi_device_Ops->disconnect(wifi_device->context);
            wifi_device->wifi_device_Ops->close(wifi_device->context);

            // reset hotspots list
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
            wifi_device->context = NULL;
            wifi_device->wifi_device_Ops = NULL;

            get_if_info(&device[index]);
        }
    }
    else if(device[index].type == DEVICE_TYPE_ETHERNET)
    {
        ret_code = ERR_CLOSE_ETHERNET_DEVICE;
        if(ifconfig_helper(device_name, 0))
            goto failed;
        ret_code = ERR_NO;
        device[index].status = DEVICE_STATUS_DOWN;
    }
    else if(device[index].type == DEVICE_TYPE_MOBILE)
    {
        ret_code = ERR_CLOSE_MOBILE_DEVICE;
        if(ifconfig_helper(device_name, 0))
            goto failed;
        ret_code = ERR_NO;
        device[index].status = DEVICE_STATUS_DOWN;
    }
    else
    {
        ret_code = ERR_DEVICE_TYPE; 
        device[index].status = DEVICE_STATUS_DOWN;
    }

    dlclose(device[index].lib_handle);
    device[index].lib_handle = NULL;
//    ifconfig_helper(device_name, 0);
failed:
    if(jo)
        json_object_put (jo);

    memset(ret_string, 0, 256);
    sprintf(ret_string, "{\"errCode\":%d, \"errMsg\":\"%s\"}", ret_code, op_errors[-1 * ret_code]);
    return ret_string;
}

char * getNetworkDevicesStatus(hbdbus_conn* conn, const char* from_endpoint, const char* to_method, const char* method_param, int *err_code)
{
    int i = 0;
    int ret_code = 0;
    char * ret_string = malloc(4096);
    char * type = NULL;
    char * status = NULL;
    int first = true;

    memset(ret_string, 0, 4096);
    sprintf(ret_string, "{\"data\":[");

    network_device * device = hbdbus_conn_get_user_data(conn);
    if(device == NULL)
    {
        ret_code = ERR_NONE_DEVICE_LIST;
        goto failed;
    }

    if(strncasecmp(to_method, METHOD_NET_GET_DEVICES_STATUS, strlen(METHOD_NET_GET_DEVICES_STATUS)))
    {
        ret_code = ERR_WRONG_PROCEDURE;
        goto failed;
    }

    for(i = 0; i < MAX_DEVICE_NUM; i++)
    {
        // get interface information
        get_if_info(&device[i]);

        if(device[i].ifname[0])
        {
            if(device[i].type == DEVICE_TYPE_WIFI)
                type = "wifi";
            else if(device[i].type == DEVICE_TYPE_ETHERNET)
                type = "ethernet";
            else if(device[i].type == DEVICE_TYPE_MOBILE)
                type = "mobile";
            else if(device[i].type == DEVICE_TYPE_LO)
                type = "lo";
            else
                continue;

            if((device[i].status == DEVICE_STATUS_UNCERTAIN) || (device[i].status == DEVICE_STATUS_DOWN))
                status = "down";
            else if(device[i].status == DEVICE_STATUS_UP)
                status = "up";
            else if(device[i].status == DEVICE_STATUS_RUNNING)
                status = "link";
            else
                status = "down";

            if(!first)
            {
                sprintf(ret_string + strlen(ret_string), ",");
            }
            first = false;

            sprintf(ret_string + strlen(ret_string), 
                    "{"
                        "\"device\":\"%s\","
                        "\"type\":\"%s\","
                        "\"status\":\"%s\","
                        "\"mac\":\"%s\","
                        "\"ip\":\"%s\","
                        "\"broadcast\":\"%s\","
                        "\"subnetmask\":\"%s\""
                    "}",
                    device[i].ifname, type, status, device[i].mac,
                    device[i].ip, device[i].broadAddr, device[i].subnetMask);
        }
        else
            break;

    }
failed:
    sprintf(ret_string + strlen(ret_string), "],\"errCode\":%d, \"errMsg\":\"%s\"}", ret_code, op_errors[-1 * ret_code]);
    return ret_string;
}

void common_register(hbdbus_conn * hbdbus_context_inetd)
{
    int ret_code = 0;

    ret_code = hbdbus_register_procedure(hbdbus_context_inetd, METHOD_NET_OPEN_DEVICE, NULL, NULL, openDevice);
    if(ret_code)
    {
        fprintf(stderr, "WIFI DAEMON: Error for register procedure %s, %s.\n", METHOD_NET_OPEN_DEVICE, hbdbus_get_err_message(ret_code));
        return;
    }

    ret_code = hbdbus_register_procedure(hbdbus_context_inetd, METHOD_NET_CLOSE_DEVICE, NULL, NULL, closeDevice);
    if(ret_code)
    {
        fprintf(stderr, "WIFI DAEMON: Error for register procedure %s, %s.\n", METHOD_NET_CLOSE_DEVICE, hbdbus_get_err_message(ret_code));
        return;
    }

    ret_code = hbdbus_register_procedure(hbdbus_context_inetd, METHOD_NET_GET_DEVICES_STATUS, NULL, NULL, getNetworkDevicesStatus);
    if(ret_code)
    {
        fprintf(stderr, "WIFI DAEMON: Error for register procedure %s, %s.\n", METHOD_NET_GET_DEVICES_STATUS, hbdbus_get_err_message(ret_code));
        return;
    }

    ret_code = hbdbus_register_event(hbdbus_context_inetd, NETWORKDEVICECHANGED, NULL, NULL);
    if(ret_code)
    {
        fprintf(stderr, "WIFI DAEMON: Error for register event %s, %s.\n", NETWORKDEVICECHANGED, hbdbus_get_err_message(ret_code));
        return;
    }
}

void common_revoke(hbdbus_conn * hbdbus_context_inetd)
{
    hbdbus_revoke_event(hbdbus_context_inetd, NETWORKDEVICECHANGED);

    hbdbus_revoke_procedure(hbdbus_context_inetd, METHOD_NET_OPEN_DEVICE);
    hbdbus_revoke_procedure(hbdbus_context_inetd, METHOD_NET_CLOSE_DEVICE);
    hbdbus_revoke_procedure(hbdbus_context_inetd, METHOD_NET_GET_DEVICES_STATUS);
}
