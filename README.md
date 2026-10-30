# bpb-panel-cpp

[BPB Panel](https://github.com/bia-pain-bache/BPB-Worker-Panel) 的 C++20 服务端重写版。

不依赖 Node.js，服务端没有任何 JavaScript/TypeScript，产物是**单个静态二进制**（面板 HTML/CSS/JS 已内嵌）：
容器镜像约 **7.5 MB**，常驻内存 **1.5 ~ 2 MB**。

上游是 Cloudflare Workers 面板；本项目保留它的订阅格式和面板接口，把运行时换成了可移植的
HTTP/WebSocket 服务 + 原生 TCP 数据面，因此同一套客户端配置可以直接跑在自己的 VPS 或容器主机上。

## 功能

- **VLESS / Trojan over WebSocket** 转原生 TCP，URL 布局与上游一致（/vl/... 、/tr/...）
- **订阅**：Xray（normal / fragment / warp / warp-pro）、sing-box、Clash/Mihomo、raw 链接、
  WireGuard 与 Amnezia 的 .conf 打包
- **面板**：沿用上游的浏览器面板，但**界面已中文化**（登录、设置、重置、my-ip、WARP 刷新、订阅、二维码）
- **DoH 反向代理**、**PNG 二维码**、**设置导入导出**
- **可选内置 TLS**（--tls-cert / --tls-key），https 与 wss 都支持；也可以交给 Caddy 终止
- **可选 WARP 出口**：通过一个侧车容器让整个面板容器经 Cloudflare WARP 出网
- **WARP 账号刷新**：直接调 Cloudflare 注册接口（X25519 + 注册），不用去控制台
- **Telegram 机器人** 的绑定 / 解绑 / webhook

## 快速开始（容器）

    docker build -t bpb-native:1.0.0 .
    docker run -d --name bpb -p 8080:8080 -v bpb-data:/data bpb-native:1.0.0

然后打开 http://<主机>:8080/securepath/panel

需要自动 HTTPS（由 Caddy 申请证书并转发 WebSocket）：

    docker compose up -d --build

首次启动会生成 data/config.json，内含随机的 VLESS UUID 和 Trojan 密码。把 mainDomain 改成客户端
实际连接的域名即可。

## 本机构建

Linux（静态链接，任意发行版可运行）：

    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build
    ./build/bpb --host 0.0.0.0 --port 8080 --data ./data

Windows（MSYS2 UCRT64，CMake 会主动拒绝 MSVC）：

    cmake -S . -B build-win -G Ninja -DCMAKE_CXX_COMPILER=A:/msys64/ucrt64/bin/g++.exe
    cmake --build build-win

命令行参数：--host、--port、--data、--tls-cert、--tls-key、--export-warp 文件、--fetch 网址。

面板资源已编译进二进制，单独一个可执行文件就能跑；需要临时替换 UI 时再用 --assets 指定目录。
数据目录（默认 ./data）不存在时会自动创建。

## 多架构 Linux 二进制

CI 会用 Alpine（musl 静态链接）编译下列架构，产物直接可拷走运行：

| 产物 | 平台 | 说明 |
|---|---|---|
| bpb-linux-amd64 | linux/amd64 | 常规 x86_64 服务器 |
| bpb-linux-arm64 | linux/arm64 | ARM 服务器、部分路由器/开发板 |
| bpb-linux-armv7 | linux/arm/v7 | 32 位 ARM（树莓派旧型号等） |
| bpb-linux-386 | linux/386 | 32 位 x86 |
| bpb-linux-riscv64 | linux/riscv64 | RISC-V |

自己本地编译某个架构（以 arm64 为例）：

    docker run --rm --platform linux/arm64 -v "$PWD:/src" -w /src alpine:3.22 sh -c '
      apk add --no-cache g++ musl-dev openssl-dev openssl-libs-static zlib-dev zlib-static
      g++ -O2 -std=c++20 -static -Isrc -Ithird_party \
          src/*/*.cpp src/main.cpp third_party/qrcodegen.cpp \
          -o bpb-linux-arm64 -lssl -lcrypto -lz -lpthread
    '

## 可选：Cloudflare WARP 出口

    docker run --rm -v "$PWD/data:/data" -v "$PWD/warp:/out" bpb-native:1.0.0 \
      --export-warp /out/wg0.conf --data /data
    docker compose -f docker-compose.warp.yml up -d --build

侧车不用 wg-quick（普通容器写不了 /proc/sys、也跑不了 resolvconf），而是手工 wg setconf +
地址 + 路由，让面板容器共享它的网络命名空间。

实测结果：WARP 握手成功，出口 IP 变成 Cloudflare WARP 地址，cdn-cgi/trace 显示 colo=SJC。
两个注意点：

- WARP 账号必须**从运行隧道的这台机器**注册（面板自己的 update-warp 用的就是容器出口）；
  经代理出口注册的账号握手永远失败；
- 部分网络下经 WARP 的 TLS 会被打断而 HTTP 正常，遇到 DoH/Telegram 失败先查这一点。

## 接口

| 路径 | 用途 |
|---|---|
| /<sp>/login、/<sp>/login/authenticate | JWT 会话 Cookie |
| /<sp>/panel、/panel/settings、/panel/update-settings、/panel/reset-settings、/panel/reset-password、/panel/logout、/panel/my-ip | 面板接口 |
| /<sp>/sub/raw\|normal\|fragment\|warp\|warp-pro?app=xray\|sing-box\|clash\|wireguard\|amnezia | 订阅 |
| /<sp>/sub/share-settings | 设置导出（base64） |
| /<sp>/dns-query | DoH 反向代理 |
| /<sp>/qrcode?data= | PNG 二维码（仅限同源地址） |
| /<sp>/panel/update-warp、/<sp>/telegram/{setup,remove,webhook} | WARP 账号、Telegram |
| /vl/<random>、/tr/<random> | VLESS / Trojan over WebSocket |

< sp > 是安全路径，默认 securepath。上游的 Cloudflare 专属功能（Worker 自部署、KV 用量统计、
面板自更新）没有实现，面板里已隐藏。

## 目录

    src/net      套接字、poll/WSAPoll 封装、HTTPS 客户端（支持 CONNECT 代理）、TLS 流
    src/http     HTTP/1.1 服务（keep-alive、WebSocket 升级）
    src/proxy    VLESS/Trojan over WebSocket -> 原生 TCP 中继
    src/sub      xray / sing-box / clash / raw / wireguard 订阅生成，WARP 注册
    src/settings JSON 设置存储（原子写）
    src/app      路由、面板接口、DoH、二维码、Telegram
    src/crypto   SHA-224/256、HMAC、HS256 JWT
    assets       浏览器面板源文件（CSS/JS 已内联），构建前由 tools/gen_assets.py 嵌入二进制
    tools/       资源嵌入脚本
    third_party  nlohmann/json、qrcodegen

## CI

.github/workflows/build.yml 在每次 push 时构建多架构二进制（amd64 / arm64 / armv7 / 386 / riscv64
和 Windows x86_64），**不产出也不发布容器镜像**。

release 任务只在**手动触发**时运行，且必须等所有架构构建成功后才执行；tag 号由手动输入，
因此不会出现"构建失败却打了 tag"的情况。

## 许可证

GPL-3.0，与上游一致。面板 HTML/CSS/JS 资源来自上游项目。