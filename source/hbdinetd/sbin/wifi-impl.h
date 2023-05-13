#ifndef __INETD_WIFI__
#define __INETD_WIFI__

char * openDevice(hbdbus_conn* conn, const char* from_endpoint, const char* to_method, const char* method_param, int *err_code);
char * closeDevice(hbdbus_conn* conn, const char* from_endpoint, const char* to_method, const char* method_param, int *err_code);
char * getNetworkDevicesStatus(hbdbus_conn* conn, const char* from_endpoint, const char* to_method, const char* method_param, int *err_code);
char * wifiStartScanHotspots(hbdbus_conn* conn, const char* from_endpoint, const char* to_method, const char* method_param, int *err_code);
char * wifiStopScanHotspots(hbdbus_conn* conn, const char* from_endpoint, const char* to_method, const char* method_param, int *err_code);
char * wifiConnect(hbdbus_conn* conn, const char* from_endpoint, const char* to_method, const char* method_param, int *err_code);
char * wifiDisconnect(hbdbus_conn* conn, const char* from_endpoint, const char* to_method, const char* method_param, int *err_code);
char * wifiGetNetworkInfo(hbdbus_conn* conn, const char* from_endpoint, const char* to_method, const char* method_param, int *err_code);

void wifi_register(hbdbus_conn * hbdbus_context_inetd);
void wifi_revoke(hbdbus_conn * hbdbus_context_inetd);

#endif  // __INETD_WIFI__
