# HBDInetd

The daemon managing network interfaces for HybridOS.

## Dependencies

- Linux WPA/WPA2/IEEE 802.1X Supplicant (2.10+):
   + Package on Ubuntu 22.04 LTS: `wpasupplicant`.
   + Source: <http://w1.fi/wpa_supplicant/>
- PurC (0.9.13+): <https://github.com/HVML/PurC>
- HBDBus (2.0.0+): <https://github.com/HybridOS2/HBDBus>

For the detailed information about the 3rd-party dependencies of HBDInetd, please refer to:

<https://github.com/HybridOS2/Documents/blob/master/ThirdPartySoftwareList.md#hbdinetd>

## Building

HBDInetd provides two ports:

- `Linux`: This port uses `wpa_supplicant` and a real implementation of DHCP client to
   scan, connect, and configure a wireless device. We use this port in a real production.
- `Fake`: This port simulating a virtual wireless device (`wlan0`). We use this port
   when we developing the app which provides the UIs for WiFi settings.

When you configure this porject by using CMake, please use one of the following commands
according to your need:

```console
$ cmake <root_of_source_tree> -DPORT=Linux
```

Or,

```console
$ cmake <root_of_source_tree> -DPORT=Fake
```

## Usage

After building HBDInetd, there will be one executable and two HVML scripts:

1. `hbdinetd`, located in the `sbin/` directory in the root of your building tree.
   This is the daemon program of HBDInetd.
1. `scan.hvml`, located in the `hvml/` directory in the root of your building tree.
   This is a HVML program for demonstrating how to use the data bus APIs to scan
   the hotspots and get the scan result from HBDInetd.
1. `connect.hvml`, located in the `hvml/` directory in the root of your building tree.
   This is a HVML program for demonstrating how to use the data bus APIs to connect to a hotspot.
   Note that you can pass the SSID and passphrase on the command line as a query string:

```console
$ hvml/connect.hvml -a cn.fmsoft.hybridos.settings -r wifi -q 'ssid=YourSSID&key=ThePassphrase'
```

To start HBDInetd, make sure that you have started HBDBus. For more information
about HBDBus, please refer to:

<https://github.com/HybridOS2/HBDBus>

After starting `hbdbusd`, you can run `hbdinetd` in the root of your building tree:

```console
$ sbin/hbdinetd
```

For the detailed usage, please run `hbdinetd` with `-h` option.

If you use Linux port, please note the following things:

1. Run `sbin/hbdinetd` as a super user (root).
1. Run `rfkill` command to cancel any blocking on the wireless devices.
1. The Linux port also needs that the executable of `wpa_supplicant` is located in the system directory `/sbin/`.
1. Some Linux distribution may configured `wpa_supplicant` under the option `ONFIG_NO_CONFIG_WRITE=y`.
   This will prevent the daemon from saving configuration to the default config file.
   However, HBDInetd needs this options having value `n`, that is, we hope `wap_supplicant` to manage the configuration.

For the description of APIs providing by HBDInetd, please refer to:

[Design of HybridOS Data Bus (Chinese)](https://github.com/HybridOS2/Documents/blob/master/zh/hybridos-design-data-bus-zh.md)
[Design of HybridOS Network Device Management Daemon (Chinese)](https://github.com/HybridOS2/Documents/blob/master/zh/hybridos-design-sysapp-inetd-zh.md)

## Copying

Copyright (C) 2020 ~ 2023 [FMSoft Technologies]

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

## Tradmarks

1) 飛漫

![飛漫](https://www.fmsoft.cn/application/files/cache/thumbnails/87f47bb9aeef9d6ecd8e2ffa2f0e2cb6.jpg)

2) FMSoft

![FMSoft](https://www.fmsoft.cn/application/files/cache/thumbnails/44a50f4b2a07e2aef4140a23d33f164e.jpg)

3) 合璧

![合璧](https://www.fmsoft.cn/application/files/4716/1180/1904/256132.jpg)
![合璧](https://www.fmsoft.cn/application/files/cache/thumbnails/9c57dee9df8a6d93de1c6f3abe784229.jpg)
![合壁](https://www.fmsoft.cn/application/files/cache/thumbnails/f59f58830eccd57e931f3cb61c4330ed.jpg)

4) HybridOS

![HybridOS](https://www.fmsoft.cn/application/files/cache/thumbnails/5a85507f3d48cbfd0fad645b4a6622ad.jpg)

5) HybridRun

![HybridRun](https://www.fmsoft.cn/application/files/cache/thumbnails/84934542340ed662ef99963a14cf31c0.jpg)

6) MiniGUI

![MiniGUI](https://www.fmsoft.cn/application/files/cache/thumbnails/54e87b0c49d659be3380e207922fff63.jpg)

7) xGUI

![xGUI](https://www.fmsoft.cn/application/files/cache/thumbnails/7fbcb150d7d0747e702fd2d63f20017e.jpg)

8) miniStudio

![miniStudio](https://www.fmsoft.cn/application/files/cache/thumbnails/82c3be63f19c587c489deb928111bfe2.jpg)

9) HVML

![HVML](https://www.fmsoft.cn/application/files/8116/1931/8777/HVML256132.jpg)

10) 呼噜猫

![呼噜猫](https://www.fmsoft.cn/application/files/8416/1931/8781/256132.jpg)

11) Purring Cat

![Purring Cat](https://www.fmsoft.cn/application/files/2816/1931/9258/PurringCat256132.jpg)

12) PurC

![PurC](https://www.fmsoft.cn/application/files/5716/2813/0470/PurC256132.jpg)

[Beijing FMSoft Technologies Co., Ltd.]: https://www.fmsoft.cn
[FMSoft Technologies]: https://www.fmsoft.cn
[FMSoft]: https://www.fmsoft.cn
[HybridOS Official Site]: https://hybridos.fmsoft.cn
[HybridOS]: https://hybridos.fmsoft.cn

[HVML]: https://github.com/HVML
[Vincent Wei]: https://github.com/VincentWei
[MiniGUI]: https://github.com/VincentWei/minigui

