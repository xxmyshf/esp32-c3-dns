# esp32-c3-adblock

一个运行在 **¥15 ESP32-C3** 上的 **Pi-hole 风格 DNS 广告拦截器** — *无需 PSRAM*。

> 基于 [M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock) 开发 — ESP-IDF 移植版，新增 OLED 显示、自定义 DNS 解析、可配置 mDNS、双语仪表盘。

> 📰 曾被 [Tom's Hardware](https://www.tomshardware.com/networking/clever-hacker-fits-537-000-domains-in-a-tiny-usd5-esp32-ad-blocking-dongle-firmware-uses-only-around-50kb-of-ram-and-can-answer-blocked-lookups-in-10-milliseconds)、[XDA Developers](https://www.xda-developers.com/this-tiny-esp32-powered-gadget-blocks-537000-domains-only-uses-50kb-of-ram/) 和 [Korben](https://korben.info/en/half-million-ad-blocking-domains-50kb-ram-esp32.html) 报道。

核心思路：不需要把屏蔽列表放进 RAM。将域名存为**排序后的 40 位哈希**写入 flash，用二分查找匹配。125,000+ 域名仅占 ~0.6 MB flash，匹配耗时 ~10 ms，占用 **~50 KB RAM**。

```
DNS 查询 ──▶ 提取域名 ──▶ FNV-1a 哈希（含父域名后缀）
         ──▶ 二分查找 flash 哈希表
              ├─ 命中 ──▶ 返回 0.0.0.0   （拦截）
              └─ 未命中 ──▶ 转发至上游 DNS，回传应答
```

## 为什么有意思

大多数 ESP32 DNS 拦截器把屏蔽列表（域名字符串）加载到 RAM，因此需要 PSRAM。本项目改用固定 **5 字节（40 位）哈希**存入 flash：

| | 字符串存 RAM | 本项目（哈希存 flash） |
|---|---|---|
| 硬件 | ESP32 + PSRAM（~$8） | ESP32-C3，无 PSRAM（~$2） |
| 125k 域名 | ~2.5 MB RAM | **0.60 MB flash** |
| RAM 占用 | 几乎全部 | **~50 KB** |
| 查找 | 字符串比较 | ~17 次 flash 读取（~10 ms，含 WiFi 往返） |
| 哈希碰撞 | 不适用 | 125k 时 0 次 |

**为什么用 40 位？** 这是当前 flash 容量的最佳平衡点。碰撞遵循生日悖论 — 125k 域名时碰撞为 0，537k 时约 1 次（即一个域名被误拦）。降到 32 位可省 20% flash，但 250k 时会有 ~7 次碰撞；升到 64 位则每个域名多浪费 3 字节来解决一个不存在的问题。

同样的方法在更大的芯片上也适用 — 并非 C3 专用方案。在 16 MB 的 ESP32-S3 上，哈希可存储 **~270 万域名**，而 8 MB PSRAM 存字符串仅 ~46.6 万。哈希存 flash 在各方面都优于字符串存 PSRAM，C3 只是让这一点更加明显。

## 功能

### DNS 拦截
- **哈希存 flash** 屏蔽列表 — 125k+ 域名，~0.6 MB，零碰撞
- **父域名后缀匹配** — 拦截 `doubleclick.net` 同时拦截 `ad.doubleclick.net`
- **自定义拦截域名** — 通过仪表盘添加/删除，或从 `.txt` 文件导入
- **预置屏蔽列表**（`data/blocklist.bin`）：StevenBlack 基础列表 + Hagezi Light + 国内广告域名
- **暂停/恢复** 拦截，支持定时（30 秒 / 5 分钟 / 30 分钟 / 永久）

### 自定义 DNS 解析
- 域名 → IP 映射（类似 hosts 文件），通过仪表盘管理
- 最多 50 条记录，持久化到 flash

### 可配置上游 DNS
- 默认：Quad9（`9.9.9.9`）
- 运行时通过仪表盘修改（如阿里 DNS `223.5.5.5`、Cloudflare `1.1.1.1`）

### Web 仪表盘（双语 🇨🇳 / 🇬🇧）
访问地址 `http://c3adblock.local`：
- 按客户端统计拦截/放行数量，封禁/解封客户端
- 添加/删除/导入/清空自定义拦截域名
- 自定义 DNS 解析管理（增删）
- 上游 DNS 配置
- DNS 查询日志（实时环形缓冲区）
- 屏蔽列表上传 & 远程自动更新（定时拉取）
- 固件 OTA 更新
- 暂停/恢复拦截（定时）
- 忘记 WiFi（返回配置门户）

### Captive Portal WiFi 配置
- 无需硬编码凭据 — 首次开机自动开启配置热点（`C3-AdBlock-XXXX`）
- 手机连接热点，选择 WiFi，输入密码
- 凭据保存到 NVS；连接失败自动重试

### OLED 显示屏
- SH1106 0.42" 72×40（01Space ESP32-C3 板），I²C 接 GPIO5/GPIO6
- 显示设备名、IP、拦截/放行计数、上游 DNS、客户端数
- WiFi 配置期间显示门户指引信息
- **GPIO9 按钮（BOOT）**：短按切换屏幕开关

### OTA 更新
- **固件** — 通过仪表盘上传 `build/c3-adblock.bin`，或 WiFi 推送
- **屏蔽列表** — 上传新的 `blocklist.bin` 或设置远程 URL 定时自动拉取
- 双 OTA 分区布局（两个 app 槽位），支持安全固件切换

### mDNS
- 设备可通过 `<主机名>.local` 发现（默认：`c3adblock`）
- **主机名可在仪表盘配置** — 修改后保存到 flash，重启生效
- 输入校验（字母、数字、连字符；最长 63 字符，符合 DNS 标签规则）

## 硬件

- 任意 **ESP32-C3** 开发板（已在 C3 SuperMini 和 01Space ESP32-C3 OLED 版上测试），4 MB flash，**无需 PSRAM**
- 使用**稳定 USB 电源**供电（手机充电器或路由器 USB 口）。劣质/松动的 USB-C→A 转接头可能在 WiFi 发射时导致电压跌落。
- 用一个 **USB-A → USB-C 转接头**可以直接插在路由器背面的空闲 USB 口上 — 无需额外电源或盒子。

### OLED 接线（可选）

| OLED | ESP32-C3 | 说明 |
|------|----------|------|
| SDA  | GPIO5    | I²C 数据 |
| SCL  | GPIO6    | I²C 时钟 |
| VCC  | 3V3      | |
| GND  | GND      | |

地址 `0x3C`。支持 SH1106 72×40（01Space 板）。显示屏为可选 — 固件自动检测，未接则跳过。

### 外壳

C3 SuperMini 的可打印外壳：[`hardware/esp32-c3-supermini-enclosure.stl`](hardware/esp32-c3-supermini-enclosure.stl)

打印注意事项：
- 无需支撑；0.2 mm 层高，~15% 填充即可。
- **保持天线端空旷。** C3 的 PCB 天线是 USB-C 口对侧短边上的锯齿形铜走线 — 不要用实心塑料覆盖或附近放金属，否则信号强度会下降。
- 保持通风口敞开：板子空闲温度约 45–55°C。

## 编译与烧录（ESP-IDF）

需要 [ESP-IDF v6.1+](https://docs.espressif.com/projects/esp-idf/en/latest/esp32c3/get-started/) 工具链。

```bash
# 0. 激活 ESP-IDF 环境
. $IDF_PATH/export.sh

# 1. 复制密钥模板（gitignore 排除，仅本地保存）并编辑：
#    - WIFI_SSID / WIFI_PASS 可选 — 留占位符，用设备上的配置门户即可。
#    - WEB_USER / WEB_PASS / OTA_PASS 用于仪表盘鉴权和网络 OTA，务必设置真实值。
cp main/secrets.example.h main/secrets.h
#    然后编辑 main/secrets.h

# 2. （可选）重新生成屏蔽列表 — 仓库已包含预置的 data/blocklist.bin
python3 tools/build_blocklist.py data/blocklist.bin

# 3. 设置目标芯片并编译
idf.py set-target esp32c3
idf.py build

# 4. 烧录固件 + 屏蔽列表文件系统（唯一一次 USB 烧录）
idf.py -p /dev/ttyACM0 flash

# 5. 查看启动日志，记下 IP / 打开仪表盘
idf.py -p /dev/ttyACM0 monitor          # -> http://c3adblock.local
```

### 烧录 SPIFFS 镜像

屏蔽列表存放在 SPIFFS 分区。仓库已包含预置的 `data/blocklist.bin`。烧录方法：

```bash
idf.py -p /dev/ttyACM0 spiffs-upload
```

或用 `esptool.py` 将 `build/spiffs_image.bin` 写入 `spiffs` 分区偏移地址（0x2b0000，见 `partitions.csv`）。

### 自定义屏蔽列表

`build_blocklist.py OUT.bin [来源 ...]` 接受 URL 和本地文件的任意组合：

- **hosts 文件** — `0.0.0.0 ads.example.com tracker.example.com`（行内所有域名均纳入）
- **纯域名** — 每行一个
- **AdGuard 格式** — `||ads.example.com^`（纳入）/ `@@||ok.example.org^`（排除）
- **正则** — `/^regex$/`（全文匹配）

默认来源（不指定时）：StevenBlack 统一 hosts + Hagezi Light。
仓库内含自定义国内广告域名列表 `data/cn-entertainment-ads.txt`，可作为额外来源合并：

```bash
python3 tools/build_blocklist.py data/blocklist.bin \
  https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts \
  https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt \
  data/cn-entertainment-ads.txt
```

## OTA 更新（无需 USB）

仪表盘 `http://c3adblock.local` 提供全部功能：

- **屏蔽列表** — 通过 *Blocklist → Upload* 上传新生成的 `blocklist.bin`，或设置 *Remote auto-update* URL 让设备定时拉取。
- **固件** — 通过 *Firmware → OTA update* 上传 `build/c3-adblock.bin`。设备验证后重启进入新镜像。

**4 MB flash 取舍：** 固件 OTA 需要两个 app 槽位，剩余 ~1.3 MB 给屏蔽列表（**最多 ~25 万域名**）。53.7 万的"ultimate"列表只能用单 app 分区表（无固件 OTA）。在 `partitions.csv` 中选择你的方案。

## 安全性

仪表盘的只读视图（`/`、`/stats.json`、`/log.json`）保持开放，但所有写操作端点都需要 **HTTP Basic Auth**（`secrets.h` 中的 `WEB_USER`/`WEB_PASS`）：

- `/ban`、`/addblock`、`/unblock`、`/forgetwifi`
- `/upload`、`/update`（屏蔽列表和固件 OTA）
- `/setupdate`、`/fetchnow`
- `/setupstream`、`/addcustomdns`、`/delcustomdns`
- `/importcustom`、`/clearcustom`
- `/setmdns`
- `/pause`、`/resume`

所有写操作端点还要求自定义 `X-Requested-With: c3-adblock` 请求头，普通 `<img>`/自动提交的 `<form>` CSRF 无法附带（只有同源 `fetch()` 可以，正是仪表盘 JS 使用的方式）。

**Basic Auth 是局域网信任边界控制，不是加密。** 所有通信为 80 端口明文 HTTP — 这个芯片没有运行 TLS 服务器的现实预算。Basic Auth 凭据是 base64 编码（非加密），每次认证请求都会发送；能嗅探局域网流量的人（开放/guest WiFi、ARP 欺骗）可以直接读取。这针对的是常见场景 — 局域网内其他设备无凭据调用 API，或浏览器标签页 CSRF — 而非中间人攻击者。

**默认凭据：** 如果 `secrets.h` 仍是 `secrets.example.h` 中的占位值 `CHANGE_ME_WEB_PASSWORD` / `CHANGE_ME_OTA_PASSWORD`，设备将以公开密码启动。在不可完全信任的网络上使用前，请务必设置真实密码。

## 使用方法

将设备的 DNS 指向 C3 的 IP，或将其作为主 DNS 后的**备用解析器**。测试：

```bash
dig @<c3-ip> doubleclick.net   # -> 0.0.0.0  （已拦截）
dig @<c3-ip> github.com        # -> 真实 IP  （已转发）
```

## 项目结构

```
├── CMakeLists.txt          # ESP-IDF 项目定义
├── partitions.csv          # 双 OTA + SPIFFS 分区表（4 MB flash）
├── sdkconfig.defaults      # 默认 Kconfig 选项
├── data/
│   ├── blocklist.bin       # 预置屏蔽列表（12.5 万域名，~0.6 MB）
│   └── cn-entertainment-ads.txt  # 自定义国内广告/追踪域名
├── main/
│   ├── main.cpp            # 固件：DNS 拦截、Web 服务器、OTA、配置门户
│   ├── oled.cpp / oled.h   # SH1106 OLED 驱动（72×40）
│   ├── page.h              # 仪表盘 HTML/JS（双语中/英）
│   ├── secrets.example.h   # WiFi/Web 鉴权模板 → 复制为 secrets.h
│   ├── CMakeLists.txt      # 组件注册
│   └── idf_component.yml   # IDF 组件清单
├── tools/
│   ├── build_blocklist.py  # hosts/域名 → 排序哈希 blob
│   └── test_build_blocklist.py
├── hardware/               # 3D 打印外壳（STL）
└── docs/                   # Web 安装器（ESP Web Tools）
```

## 注意事项

- **ModemManager**（Fedora/Ubuntu 默认安装）会占用 `/dev/ttyACM0` 并切换 DTR/RTS，导致 **C3 复位**并阻塞串口。解决方法：
  ```bash
  sudo systemctl stop ModemManager
  echo 'ATTRS{idVendor}=="303a", ENV{ID_MM_DEVICE_IGNORE}="1"' | sudo tee /etc/udev/rules.d/99-esp-no-modemmanager.rules
  sudo udevadm control --reload-rules && sudo udevadm trigger
  ```
- C3 的 USB-Serial-JTAG 控制台可能在主机连接前丢失早期启动输出。
- DNS 客户端会添加 **EDNS OPT** 记录；拦截应答必须只包含问题和回答（ANCOUNT=1，NSCOUNT=ARCOUNT=0），否则应答格式错误。

## 鸣谢

灵感来自 [s60sc/ESP32_AdBlocker](https://github.com/s60sc/ESP32_AdBlocker) — "对屏蔽列表域名返回 0.0.0.0"的思路。本项目是独立从头实现，专注于无 PSRAM 芯片的哈希存 flash 优化。

## 许可证

MIT — 见 [LICENSE](LICENSE)。
