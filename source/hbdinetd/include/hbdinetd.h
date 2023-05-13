#ifndef __INETD__H__
#define __INETD__H__

/* Architecture of software layers 
    runner layer:                           inetd (main.c)
                                              |
                      --------------------------------------------------------
                      |                       |                              |
    hiBus layer:   mobile.c             wifi.c(src/inted)                ethernet.c
                                              |
    control layer:                      wifi.so(src/wifi)
                                              |
    tools layer(optional):              wifimanager.so
                                              |
    system service layer                wpa_supplicant
                                              |
    hardware layer                       WiFi Device

    runner layer: manage each network device and initialize hiBus context.
    hiBus layer: handle the data from hibus, such as procedure and message.
    control layer: control the hardware device.
    tools layer: assistant tools for control if any.

*/


#include "user_define.h"

// method for All Network Devices 
#define METHOD_NET_OPEN_DEVICE          "openDevice"
#define METHOD_NET_CLOSE_DEVICE         "closeDevice"
#define METHOD_NET_GET_DEVICES_STATUS   "getNetworkDevicesStatus"
// method for WiFi Device
#define METHOD_WIFI_START_SCAN          "wifiStartScanHotspots"
#define METHOD_WIFI_STOP_SCAN           "wifiStopScanHotspots"
#define METHOD_WIFI_CONNECT_AP          "wifiConnect"
#define METHOD_WIFI_DISCONNECT_AP       "wifiDisconnect"
#define METHOD_WIFI_GET_NETWORK_INFO    "wifiGetNetworkInfo"
// method for Ethernet Device
// method for Mobile Device


// event for All Network Devices
#define NETWORKDEVICECHANGED            "NETWORKDEVICECHANGED"
// event for WiFi Device
#define WIFIHOTSPOTSCHANGED             "WIFIHOTSPOTSCHANGED"
#define WIFISIGNALSTRENGTHCHANGED       "WIFISIGNALSTRENGTHCHANGED"
// event for Ethernet Device
// event for Mobile Device

// parameter for inetd runner
#define APP_NAME_SETTINGS               "cn.fmsoft.hybridos.settings"
#define RUNNER_NAME_INETD               "inetd"
#define SOCKET_PATH                     "/var/tmp/hibus.sock"
#define MAX_DEVICE_NUM                  10          // maximize of network devices is 10
#define DEFAULT_SCAN_TIME               30          // for WiFi scan  period

// device type
#define DEVICE_TYPE_UNKONWN             0
#define DEVICE_TYPE_ETHERNET            1
#define DEVICE_TYPE_WIFI                2
#define DEVICE_TYPE_MOBILE              3
#define DEVICE_TYPE_LO                  4
#define DEVICE_TYPE_DEFAULT             DEVICE_TYPE_ETHERNET

// device status
#define DEVICE_STATUS_UNCERTAIN         0           // uncertain
#define DEVICE_STATUS_DOWN              1           // device is unactive
#define DEVICE_STATUS_UP                2           // device is active, but perhaps do not connect to any network
#define DEVICE_STATUS_RUNNING           3           // device is active and has ip address

// for error
#define ERR_NO                          0
#define ERR_LIBRARY_OPERATION           -1
#define ERR_NONE_DEVICE_LIST            -2
#define ERR_WRONG_PROCEDURE             -3
#define ERR_WRONG_JSON                  -4
#define ERR_NO_DEVICE_NAME_IN_PARAM     -5
#define ERR_NO_DEVICE_IN_SYSTEM         -6
#define ERR_DEVICE_TYPE                 -7
#define ERR_LOAD_LIBRARY                -8
#define ERR_NOT_WIFI_DEVICE             -9
#define ERR_DEVICE_NOT_OPENNED          -10
#define ERR_OPEN_WIFI_DEVICE            -11
#define ERR_CLOSE_WIFI_DEVICE           -12
#define ERR_OPEN_ETHERNET_DEVICE        -13
#define ERR_CLOSE_ETHERNET_DEVICE       -14
#define ERR_OPEN_MOBILE_DEVICE          -15
#define ERR_CLOSE_MOBILE_DEVICE         -16
#define ERR_DEVICE_NOT_CONNECT          -17
#define ERR_LIB_DEVICE_DISABLE          -18
#define ERR_LIB_INVALID_SSID            -19
#define ERR_LIB_INVALID_PASSWORD        -20
#define ERR_LIB_DEVICE_BUSY             -21
#define ERR_LIB_NET_EXISTENCE           -22
#define ERR_LIB_ADD_NETWORK             -23
#define ERR_LIB_SET_NETWORK             -24
#define ERR_LIB_SELECT_NETWORK          -25
#define ERR_LIB_ENABLE_NETWORK          -26
#define ERR_LIB_RECONNECT_NETWORK       -27
#define ERR_LIB_WRONG_PASSWORD          -28

// for network changed
#define NETWORK_CHANGED_NAME            ((0x01) << 0)
#define NETWORK_CHANGED_TYPE            ((0x01) << 1)
#define NETWORK_CHANGED_STATUS          ((0x01) << 2)
#define NETWORK_CHANGED_MAC             ((0x01) << 3)
#define NETWORK_CHANGED_IP              ((0x01) << 4)
#define NETWORK_CHANGED_BROADCAST       ((0x01) << 5)
#define NETWORK_CHANGED_SUBNETMASK      ((0x01) << 6)

// for string length
#define HOTSPOT_STRING_LENGTH           64 
#define NETWORK_DEVICE_NAME_LENGTH      32
#define NETWORK_ADDRESS_LENGTH          32

/*
    Architecture of structures

                    |-- type        according to   |-- Ethnet_device (for Ethernet)
    network_device--|-- * device <-----------------|-- WiFi_device (for WiFi)
                    |-- ifname      device type    |-- Mobile_device (for Mobile)
*/

// network device description
typedef struct _network_device
{
    char ifname[NETWORK_DEVICE_NAME_LENGTH];    // device name
    int type;                                   // device type: DEVICE_TYPE_XXX
    unsigned int status;                        // device status: DEVICE_STATUS_XXX
    int priority;                               // device priority
    void * device;                              // specified structure pointer for a device type. 
                                                // e.g. WiFi_device structure for WiFi device
    char mac[NETWORK_ADDRESS_LENGTH];           // MAC address
    char ip[NETWORK_ADDRESS_LENGTH];            // IP address
    char broadAddr[NETWORK_ADDRESS_LENGTH];     // broadcast address
    char subnetMask[NETWORK_ADDRESS_LENGTH];    // subnet mask
    int speed;                                  // network speed
    char libpath[HOTSPOT_STRING_LENGTH];        // library path
    void * lib_handle;                          // handle of library. e.g. for wifi.so
} network_device;

// WiFi device description
typedef struct _WiFi_device                     // WiFi device description
{
    struct _hiWiFiDeviceOps * wifi_device_Ops;  // the operations for control layer
    struct _wifi_context * context;             // the context for WiFi control layer 
    char bssid[HOTSPOT_STRING_LENGTH];          // bssid of current connecting network
    int signal;                                 // signal strength for current connecting network
    int scan_time;                              // the internal time for scan network
    pthread_mutex_t list_mutex;                 // for hotspots list
    struct _wifi_hotspot *first_hotspot;        // hotspots list
} WiFi_device;

// WiFi AP description
typedef struct _wifi_hotspot                    // the information for one AP
{
    char bssid[HOTSPOT_STRING_LENGTH];          // bssid
    unsigned char ssid[HOTSPOT_STRING_LENGTH];  // ssid
    char frenquency[HOTSPOT_STRING_LENGTH];     // frequency
    char capabilities[HOTSPOT_STRING_LENGTH];   // encrypt type
    int  signal_strength;                       // signal strength
    int isConnect;                              // whether connected
    struct _wifi_hotspot * next;                // the next node in list
} wifi_hotspot;

// wifi context of control layer
typedef struct _wifi_context                    // context get from control layer
{
    const aw_wifi_interface_t* p_wifi_interface;// context of tools layer. WiFi is a bit complicated。
    int event_label;                            // lable code for wifimanager
} wifi_context;

// interface of libwifi.so
typedef struct _hiWiFiDeviceOps
{
    int (* open) (const char * device_name, wifi_context ** context);           // open wifi device
    int (* close) (wifi_context * context);                                     // close wifi device
    int (* connect) (wifi_context * context, const char * ssid, const char *password);
    int (* disconnect) (wifi_context * context);
    int (* start_scan) (wifi_context * context);
    int (* stop_scan) (wifi_context * context);
    unsigned int (* get_hotspots) (wifi_context * context, wifi_hotspot ** hotspots);       
    int (*get_cur_net_info)(wifi_context * context, char * reply, int reply_length);
    int (*set_scan_interval)(wifi_context * context, int interval);
    void (* report_wifi_scan_info)(char * device_name, int type, void * hotspots, int number);
} hiWiFiDeviceOps;

// for test
#define AGENT_NAME          "cn.fmsoft.hybridos.sysmgr"
#define AGENT_RUNNER_NAME   "gui"

#endif  // __INETD__H__
