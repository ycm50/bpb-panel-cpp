# bpb-panel-cpp

[BPB Panel](https://github.com/bia-pain-bache/BPB-Worker-Panel) 的 **C++20 服务端重写版**。

上游是跑在 Cloudflare Workers 上的面板；本项目保留它的订阅格式与面板接口，
把运行时换成可移植的 HTTP/WebSocket 服务 + 原生 TCP 数据面，外加一个自研的
Cloudflare Tunnel 客户端。**服务端没有任何 JavaScript/TypeScript**，产物是
**单个静态二进制**，面板 HTML/CSS/JS 已内嵌其中。

| 指标 | 实测值 |
|---|---|
| 二进制（Linux 静态） | 约 9 MB（替换了 40 MB 的 cloudflared） |
| 常驻内存 | **6.5 MB**（压力下 9.5 MB，峰值 11.6 MB）；实测见 [性能](#性能实测) |
| 空闲 CPU | **0.02%** 单核 |
| 满速 1 MB/s 传输 | 约 44% 单核（TLS 加解密开销） |

## 目录

- [功能](#功能)
- [分支说明](#分支说明)
- [快速开始](#快速开始)
- [安装脚本](#一条命令安装linux)
- [从源码构建](#从源码构建)
- [命令行](#命令行)
- [入栈协议与按协议构建](#入栈协议与按协议构建)
- [日志开关](#日志开关)
- [接口](#接口)
- [客户端怎么连](#客户端怎么连)
- [Cloudflare Tunnel](#cloudflare-tunnel)
- [数据面：WebSocket 入栈](#数据面websocket-入栈)
- [WARP 出口](#warp-出口)
- [性能实测](#性能实测)
- [架构](#架构)
- [测试](#测试)
- [CI 与发布](#ci-与发布github-actions)
- [许可证](#许可证)

## 分支说明

| 分支 | WARP 出栈 | 特点 |
|---|---|---|
| `warp-built-in`（默认分支） | 进程内 `src/wg` + lwIP | 单二进制、零外部依赖、内存更省 |
| `warp-rust` | 独立进程 `warp-rust`（Rust，自带用户态栈） | bpb 负责渲染配置、监督生命周期，经本地 SOCKS5 转发 |

两个分支的**面板、订阅、隧道功能完全一致**，差异只在 WARP 数据面。

## 功能

- **四种入栈，各自独立成文件、按需编译**：VLESS（`/vl`）、Trojan（`/tr`）、
  Shadowsocks（`/ss`）、VMess（`/<uuid>-vm`）。全部把 WebSocket 还原成原生 TCP 后转发；
  没编进二进制的协议既不参与编译、也不响应（见 [入栈协议](#入栈协议与按协议构建)）
- **每协议一个独立二进制**：release 里是 `bpb-linux-<arch>-<协议>`，
  `all` = 四个协议各出一个，不是塞进同一个二进制
- **订阅**：Xray（normal / fragment / warp / warp-pro）、sing-box、Clash/Mihomo、
  raw 链接、WireGuard 与 Amnezia 的 `.conf` 打包
- **面板**：沿用上游界面并中文化（登录、设置、重置、my-ip、WARP 刷新、订阅、二维码）
- **DoH 反向代理**、**PNG 二维码**、**设置导入导出**
- **可选内置 TLS**（`--tls-cert` / `--tls-key`），https 与 wss 都支持；也可交给 Caddy 终止
- **内置 Cloudflare Tunnel 客户端**：不需要 cloudflared，注册、转发、断线重连全在进程内
- **WARP 出口**：两种实现，见 [WARP 出口](#warp-出口) ——
  独立进程 `warp-rust`（`warp-rust` 分支）或**内置用户态 WireGuard**
  （`warp-built-in` 分支也就是默认分支，Noise IK + lwIP，无需特权）
- **面板内注册 WARP 账号**：默认 **dry run** —— 只构造并打印请求体、
  返回合成账号，**不访问 Cloudflare**、不写账号池
- **隧道按需唤醒 / 休眠**：临时隧道不常驻，用的时候一句话拉起；
  注册到的域名会**自动同步成订阅主域名**，不再需要手改 `mainDomain`
- **Telegram 机器人**的绑定 / 解绑 / webhook

## 快速开始

### 一条命令安装（Linux）

    curl -fsSL https://raw.githubusercontent.com/ycm50/bpb-panel-cpp/warp-built-in/install.sh | sh

或者先下载再带参数运行：

    sh install.sh --port 8080

脚本会：**按 `uname -m` 选架构下载**对应静态二进制（amd64 / arm64 / armv7 / 386 / riscv64）
→ 校验 `SHA256SUMS` → 装成 systemd 服务（开机自启、崩溃自拉起）→
**自动开一条临时 Cloudflare 隧道**并打印面板的公网域名。

| 参数 | 说明 |
|---|---|
| `--port N` | 面板端口；**同时作为隧道回源端口**（默认 8080） |
| `--data DIR` | 数据目录，默认 `/root/.bpbdata` |
| `--tag TAG` | 安装指定 release，默认 `latest` |
| `--local PATH` | 不下载，直接安装本地已有的二进制 |
| `--protocol NAME` | 该二进制编入的入栈协议，默认 `vless`（release 里是 `bpb-linux-<arch>-<协议>`） |
| `--no-tunnel` | 不开隧道，只在本机端口提供面板 |
| `--uninstall` | 停服务并删除，数据目录保留 |

装完会打印三段地址：

    面板（本机）: http://127.0.0.1:8080/securepath/panel
    面板（公网）: https://<随机>.trycloudflare.com/securepath/panel
    隧道域名    : <随机>.trycloudflare.com

注意两点：

- **`--port` 必须同时决定隧道回源端口**。`cfTunnel.originPort` 在二进制里写死默认 8080，
  面板跑在别的端口时若不同步这个值，隧道会注册成功但转发到一个没人听的端口。
  脚本已经处理了这一点（新建和已有 `settings.json` 都会改）。
- **`--data` 不是默认值时是独立实例**：服务名变成 `bpb-<目录 slug>`、二进制装到
  `/usr/local/lib/`，不会覆盖 `bpb.service`。用它在同一台机器上测试不会踢掉正式面板。
  对应地用 `sh install.sh --uninstall --data <那个目录>` 卸载。

临时隧道的域名不保证长期有效。要固定域名就填命名隧道 token：
`/<sp>/panel` → Cloudflare 隧道 → 隧道 Token。

### Docker

    docker build -t bpb-native:1.0.0 .
    docker run -d --name bpb -p 8080:8080 -v bpb-data:/data bpb-native:1.0.0

打开 <http://localhost:8080/securepath/panel>。

首次启动会生成 `.bpbdata/config.json`（含随机 VLESS UUID）与 `.bpbdata/settings.json`。

`mainDomain` 是订阅里客户端连接的地址：

- 用**命名隧道**（`cfTunnel.token` 有值）→ 自己填成隧道绑定的域名
- 用**临时隧道**（`cfTunnel.token` 留空）→ **留空即可**，注册成功后会自动改写为
  分配到的 `*.trycloudflare.com` 域名并落盘

需要自动 HTTPS（由 Caddy 申请证书并转发 WebSocket）：

    docker compose up -d --build

## 从源码构建

### Linux（静态链接，任意发行版可运行）

    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build
    ./build/bpb --host 0.0.0.0 --port 8080 --data ./.bpbdata

依赖：GCC/Clang（支持 C++20）、OpenSSL、zlib。CMake 会**主动拒绝 MSVC**。

要和 CI 一样产出「扔到任何发行版都能跑」的静态二进制，用：

    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBPB_STATIC=ON
    cmake --build build

`BPB_STATIC=ON` 会让 CMake 去找 `libssl.a`/`libz.a`；只加 `-static` 是不够的，
链接器会去解 `libssl.so` 然后报 "attempted static link of dynamic object"。
（不要手写 `g++` 单行命令：它拿不到 lwIP 的 include 路径，而且源文件分层
`src/inbound/proto/` 之后通配符会漏文件。）

### Windows（MSYS2 UCRT64）

    cmake -S . -B build-win -G Ninja -DCMAKE_CXX_COMPILER=A:/msys64/ucrt64/bin/g++.exe
    cmake --build build-win

## 命令行

| 参数 | 说明 |
|---|---|
| `--host <ip>` | 监听地址，默认 `0.0.0.0` |
| `--port <n>` | 监听端口，默认 `8080` |
| `--data <dir>` | 数据目录，默认 `./.bpbdata`，不存在会自动创建 |
| `--assets <dir>` | 改用指定目录的面板资源（跳过首次释放，正常不需要） |
| `--tls-cert` / `--tls-key` | 启用 HTTPS / wss |
| `--export-warp <file>` | 导出侧车用的 `wg0.conf` |
| `--fetch <url>` | 出网诊断 |
| `--log <level>` | 日志级别，默认 `error`（见下） |

## 入栈协议与按协议构建

各入栈协议是**独立源文件**，用 CMake 选项选择编哪些，没选中的**不参与编译**
（不是运行时关掉，是根本不进二进制）：

    -DBPB_INBOUNDS=vless                只编 VLESS
    -DBPB_INBOUNDS=vless,trojan         指定组合
    -DBPB_INBOUNDS=all                  全部
    # 配置期会打印： -- bpb inbounds: vless;trojan;shadowsocks;vmess

| 协议 | 路径 | 说明 |
|---|---|---|
| VLESS | `/vl` | 支持 `?ed=` early data |
| Trojan | `/tr` | hex(SHA224(密码)) 认证 |
| Shadowsocks | `/ss` | SIP004 AEAD，固定 aes-256-gcm |
| VMess | `/<uuid>-vm` | AEAD 头 + AES-128-GCM / ChaCha20-Poly1305，支持 WS early data |

四者共用面板 UUID 当凭据（VLESS/VMess 的 UUID、Trojan 的口令、SS 的 AEAD 密码），
所以不用额外配置。VMess 的路径由凭据决定，因此分发时对路径做的是**动态匹配**
（`Inbound.match`）而不是比字符串。回环与 RFC1918 目标自动直连，其余走 WARP。

面板会跟着编译期清单走：`/panel/settings` 返回 `inbounds` 数组，
`update-settings` 会剔除没编进来的协议（一个不剩时返回 400），订阅生成也取这个交集。

启动日志（需要 `--log info`）会写实际编入的协议：

    bpb native listening on http://0.0.0.0:8080 (secure path: /securepath/, inbounds: vless,trojan,shadowsocks,vmess)

面板资源已编译进二进制，**单独一个可执行文件就能跑**。

## 日志开关

**默认关**：级别是 `error`，正常运行 stderr 一个字节都不输出，只有真出错才说话。
以前一次三小时的会话能刷出 47 万行（每秒每流一条、每条请求一条、外加逐帧 trace），
在小机器上光是写 journal 都是可观的 CPU，所以现在默认闭嘴。

    bpb --log info      # 注册、边缘连接、隧道主机名
    bpb --log debug     # 每条请求、每秒流量统计
    bpb --log trace     # 每个 HTTP/2 帧（原 BPB_TUNNEL_TRACE=1）

也可以只用环境变量：`BPB_LOG=info` / `BPB_LOG=debug` / `BPB_LOG=trace`，
命令行优先。`BPB_TRACE=1`、`BPB_TUNNEL_TRACE=1`、`BPB_WG_TRACE=1` 仍然有效，
等价于 `trace`，旧的排查脚本不用改。

**隧道域名只在安装时打印**：`install.sh` 结尾会输出一行 `隧道域名 : xxx`；
bpb 自己启动时不再重复喊，要看随时查面板或
`/<sp>/panel/tunnel-status`。

首次启动会把面板释放到数据目录，之后**每次请求都直接从磁盘读**：

    .bpbdata/
      config.json            # mainDomain / securePath / vlUUID ...
      settings.json          # 面板设置、密码、WARP 账号
      favicon.ico
      assets/
        panel/index.html     # 改完刷新页面即可生效，不用重启、不用重编译
        login/index.html
        error/index.html

已存在的文件**不会被覆盖**，所以本地改过的样式在升级后仍在；
删掉某个文件则自动回退到内嵌副本（不会出现 404）。
进程不缓存这些页面，修改后下一次请求就是新的。

## 接口

| 路径 | 用途 |
|---|---|
| `/<sp>/login`、`/<sp>/login/authenticate` | JWT 会话 Cookie |
| `/<sp>/panel` 及 `/panel/{settings,update-settings,reset-settings,reset-password,logout,my-ip}` | 面板接口 |
| `/<sp>/sub/raw\|normal\|fragment\|warp\|warp-pro?app=xray\|sing-box\|clash\|wireguard\|amnezia` | 订阅 |
| `/<sp>/sub/share-settings` | 设置导出（base64） |
| `/<sp>/dns-query` | DoH 反向代理 |
| `/<sp>/qrcode?data=` | PNG 二维码（仅限同源地址） |
| `/<sp>/panel/warp-status` | 出栈状态（后端类型、ready、账号数、是否 dry run） |
| `/<sp>/panel/warp-register` | 注册 WARP 账号（**默认 dry run**，返回 `saved:false` 表示未写账号池） |
| `/<sp>/panel/tunnel-status` | 隧道状态：`running/connected/registered`、`hostname`/`url`、`hostnames`（ingress 全部主机名）、`mainDomain`（订阅当前域名） |
| `/<sp>/panel/tunnel-wake` / `tunnel-sleep` | 唤醒 / 休眠（都返回与 status 同构的最新状态） |
| `/<sp>/panel/update-warp`、`/<sp>/telegram/{setup,remove,webhook}` | WARP 账号、Telegram |
| `/vl` | VLESS over WebSocket（支持 `?ed=` early data） |
| `/tr` | Trojan over WebSocket（`hex(SHA224(uuid))` 作口令） |
| `/ss` | Shadowsocks over WebSocket（SIP004，固定 aes-256-gcm） |
| `/<uuid>-vm` | VMess over WebSocket（AEAD 头，支持 early data） |

`<sp>` 是安全路径，默认 `securepath`。上游的 Cloudflare 专属功能
（Worker 自部署、KV 用量统计、面板自更新）没有实现，面板里已隐藏。

## 客户端怎么连

四条入栈共用面板的 UUID 当凭据（VLESS/VMess 的 id、Trojan 的口令、SS 的 AEAD 密码），
路径固定，传输都是 WebSocket：

| 协议 | 客户端要点 |
|---|---|
| VLESS | `id=UUID`、`encryption=none`、ws path `/vl`（可加 `?ed=2560`） |
| Trojan | `password=UUID`、ws path `/tr`；TLS 由前置（Cloudflare/Caddy）决定 |
| Shadowsocks | `method=aes-256-gcm`、`password=UUID`、ws path `/ss` |
| VMess | `id=UUID`、`alterId=0`、`security=auto`、ws path `/<uuid>-vm`（可加 `?ed=2048`） |

VMess 的两种客户端写法（与 yonggekkk/argosbx 一致）：

```json
// Xray（security=none 是 WS 层，外层有 TLS 时是 https/wss）
{ "protocol": "vmess",
  "settings": { "vnext": [ { "address": "<域名或优选IP>", "port": 443,
    "users": [ { "id": "<uuid>", "alterId": 0, "security": "auto" } ] } ] },
  "streamSettings": { "network": "ws", "security": "none",
    "wsSettings": { "path": "/<uuid>-vm" } } }
```

```json
// sing-box
{ "type": "vmess", "server": "<域名>", "server_port": 443,
  "uuid": "<uuid>", "alter_id": 0, "security": "auto",
  "transport": { "type": "ws", "path": "/<uuid>-vm",
    "max_early_data": 2048,
    "early_data_header_name": "Sec-WebSocket-Protocol" } }
```

raw 订阅里给的是 `vmess://base64({...})` 分享链接，字段
`v=2 / aid=0 / scy=auto / net=ws / type=none / path=/<uuid>-vm`；
TLS 端口会带 `tls=tls` 加 `sni/alpn/fp`，明文端口 `tls` 留空。

面板与订阅都会跟着编译期清单裁剪：二进制里没有的协议不会出现在
`/panel/settings` 的 `inbounds` 里，也生成不出对应链接（提交不存在的协议返回 400）。

## Cloudflare Tunnel

面板里打开隧道开关后，进程会自己注册到 Cloudflare 边缘，把公网请求转发回本机
监听端口，不再需要 40 MB 的 cloudflared。

**两种取凭据的方式**：

- `cfTunnel.token` 填了值 → 走**命名隧道**，域名由你自己的 Cloudflare 账号决定
- `cfTunnel.token` 为**空** → 自动注册**临时隧道**（`POST api.trycloudflare.com/tunnel`），
  拿到 `{id, account_tag, secret, hostname}`，拼成同样的 `{"a","t","s"}` token 后照常连接。
  凭据落在 `.bpbdata/tunnel-quick.json`，**重启复用同一个域名**，不会每次都注册新的

**隧道域名从哪来**：连接器 token 本身只有 `{"a","t","s"}`（账号、隧道 UUID、密钥），
**不含域名**；能查到域名的 REST 接口
（`GET /accounts/<acct>/cfd_tunnel/<uuid>` 或 `.../configurations`）需要**账号级 API Token**，
而 token 模式的凭据不是 API Token，直接调用只会得到
`9106 Missing X-Auth-Key, X-Auth-Email or Authorization headers`。

所以域名取自**边缘主动推送的 ingress 配置**——它本来就走隧道自己的控制流：

    {"version":2,"config":{"ingress":[
      {"hostname":"bytevirt.5704524.xyz","service":"http://localhost:23456"},
      {"service":"http_status:404"}],
     "warp-routing":{"enabled":false}}}

解析在 `src/tunnel/ingress.h`（纯函数，可直接单测）。`tunnel-status` 会把
`hostnames`（全部 ingress 主机名）`hostname`/`url`（实际采用的那个）以及
`mainDomain`（订阅当前使用的域名）一起返回，面板上对应
「隧道域名（回源入口）」与「订阅使用的域名」两行。

**订阅自动使用隧道域名**：拿到 ingress 主机名后写入 `config.json` 的 `mainDomain`
并落盘（日志打印旧值 → 新值）。订阅是按请求实时渲染的，下一次拉订阅就指向可用地址。
只有当 `mainDomain` 为空、仍是出厂值 `localhost`、或本身就是上一次自动写入的值时才会覆盖，
**手工填过的域名不会被抢**。

同样地，临时隧道注册成功时也会把 `mainDomain` 改成它分配到的
`*.trycloudflare.com`。这一点很关键——曾经因为 `mainDomain` 还停在一条已经死掉的
命名隧道上，隧道本身健康、面板却发出一堆连不上的配置。

**按需唤醒**：`tunnel-sleep` 关掉连接、面板回到待机；`tunnel-wake` 再拉起，
不常驻一个边缘连接。休眠后状态立刻变为 `running:false`，
唤醒后先报 `connected:false` 再随注册完成翻成 `true`，不会出现"睡着却显示在跑"。

> **已知限制**：`.bpbdata/tunnel-quick.json` 里的凭据如果已在 Cloudflare 侧失效
> （比如手动 sleep 过），重启会**复用这份死凭据**，域名 DNS 解析不到、面板打不开。
> 当前的处理是删掉该文件后重启重新注册；尚未做启动时的可用性校验。

实现要点（均对照 cloudflared / Xray-core 源码验证）：

- TCP 7844 + TLS（SNI `h2.cftunnel.com`，不协商 ALPN），**HTTP/2 由本进程作为服务端**
- capnp RPC over StreamTransport，消息**无长度前缀**
- 用户头以 `b64(name):b64(value);...` 序列化进 `cf-cloudflared-response-headers`
- HTTP/2 禁止 101，WebSocket 升级映射为 **200**；`Sec-WebSocket-Protocol` 必须原样回写
  （Xray 用它承载 early data）
- 回源连接是**非阻塞状态机**（`OriginStream::begin/step`），**h2 回调里绝不等待回源响应**，
  否则带 body 的请求会互相等待而死锁
- 边缘断线（EOF / GOAWAY / 读写失败）由监督线程以 1s~30s 指数退避重连并重新注册

## 数据面：WebSocket 入栈

四种入栈（VLESS / Trojan / Shadowsocks / VMess）共用同一条数据面设计：把 WebSocket
还原成原始字节流，再用**两个线程**分别搬运两个方向，等价于 cloudflared
`stream.Pipe` 的两个 goroutine：

    client -> upstream   (读 WS 帧，写回源 socket)
    upstream -> client   (读回源 socket，写 WS 帧)

单线程 poll 调度会让慢方向拖死快方向，表现为大响应在约 3 KB 处停住、
15 秒后被边缘 RST。这是本项目踩过的最深的坑，回归测试见
[TESTS.md](TESTS.md) 第 2c 节。

其它相关细节：

- **HTTP 服务侧启用 `SSL_MODE_ENABLE_PARTIAL_WRITE`**：非阻塞 socket 上
  `SSL_write` 遇到 `WANT_WRITE` 会一个字节都不消费，不开启就永远写不完大响应
- 响应体按 16 KB 分片写，避免一次把 1 MB 全塞进 SSL 层
- 半关闭（`shutdown(SHUT_WR)`）的请求仍必须**应答完再关**，否则随机 502
- 会话结束时发送 RFC 6455 close 帧（1000 normal），否则客户端报
  `close 1006 (abnormal closure)`

## WARP 出口

出口就是把 VLESS 会话的上游连接接进 WARP。两种后端，面板接口完全一致：

| 后端 | 分支 | 形态 |
|---|---|---|
| 内置 `src/wg` + lwIP | `warp-built-in`（默认分支） | 进程内用户态 TCP/IP 栈直连 WireGuard，不需要外部程序也不需要 `NET_ADMIN` |
| `warp-rust` | `warp-rust` | 外部独立进程；bpb 渲染 `warp-rust.toml`、监督生命周期，数据经本地 SOCKS5（`127.0.0.1:11080`）转发 |

另有 **侧车容器**（整机出网，需 `NET_ADMIN`）：

    docker run --rm -v "$PWD/data:/data" -v "$PWD/warp:/out" bpb-native:1.0.0 \
      --export-warp /out/wg0.conf --data /data
    docker compose -f docker-compose.warp.yml up -d --build

侧车不用 `wg-quick`（普通容器写不了 `/proc/sys`、也跑不了 `resolvconf`），
而是手工 `wg setconf` + 地址 + 路由，让面板容器共享它的网络命名空间。

### 面板里的注册（默认 dry run）

`warpRegisterDryRun` 默认 **`true`**：

- **dry run**：生成 X25519 密钥对、构造请求体、打印日志，返回**合成账号**，
  响应里 `saved:false`，**完全不联网**
- 关掉之后才会真正 `POST api.cloudflareclient.com` 并写入账号池

之所以默认 dry run：Cloudflare 对注册接口按来源 IP 限流，开发和演示不该消耗配额。
另外 dry run **绝不写账号池** —— 合成账号没有可用密钥，写进去会让下次启动拿到一个死账号。

### 内置用户态 WireGuard（`warp-built-in`）

| 目录 | 内容 |
|---|---|
| `src/wg/` | Noise_IKpsk2 握手与传输封装：X25519、HKDF-HMAC-BLAKE2s、ChaCha20-Poly1305、TAI64N、mac1 |
| `src/net/wg_stack` | 内嵌 lwIP 用户态 TCP/IP 栈，`nif->output` 直连 WireGuard 传输层 |
| `third_party/lwip` | 裁剪到 core + IPv4 的 lwIP（BSD 许可） |

账号同样复用 `warpAccounts[0]`，不重复注册。

实测（1 核 / 512 MB）：

| 后端 | 结果 |
|---|---|
| 内置（`warp-built-in`） | 连续 10 次 HTTPS 经 VLESS → bpb → WARP 全部成功，出口均为 WARP 地址，平均 1.5 秒；100 KB 下载完整 |
| `warp-rust` 后端（`warp-rust` 分支） | 常驻约 **7.4 MB**（bpb 2.4 MB + warp-rust 5.2 MB），同样 10 次连续成功 |

### 踩过的坑（都已修掉，列出来便于以后排查）

1. **握手应答没人收**：lwIP 靠 `pump()` 前进，而 `pump()` 只在 `connect()` 里调用，
   `connect()` 又要求在 `ready()` 为真时才被调用 —— 循环依赖，`has_session()` 永远为假。
   修法：加自驱线程，每 10 ms `pump()`，无会话时重发握手。
2. **`start_wg_outbound()` 谎报成功**：握手失败也返回 true，日志打 "enabled" 而实际全走直连。
   改成等待 6 秒，只有 `ready()` 为真才返回 true。
3. **lwIP 无锁访问**：`pump()` 与 `WgConnection::write()` 在不同线程动同一个 pcb，收进栈锁。
4. **`tcp_close` 失败导致 pcb 滞留**：返回非 `ERR_OK` 时改走 `tcp_abort`。
5. **对端静默作废会话后永不恢复**：WARP 会一声不吭停止回包，而本地 `has_session()` 仍为真，
   驱动不会重握手 → 隧道死于重启前。加了「无接收 15 秒且期间有发送就丢弃会话强制重握手」的看门狗。
6. **MTU 1280 的整段被丢**：超过 1 个 MSS 的上传（例如 1520 字节的 TLS ClientHello）要拆两段，
   而 1280 字节的整段在这条路径上会被静默丢弃 → 握手卡死。**默认 MTU 改为 1200**。
7. **relay 读写共用一把锁**：下载方向持锁做 100 ms 阻塞轮询、释放后立刻又抢回来，
   上传方向被饿死 —— 客户端发完握手包后，请求排不进去，源站等不到数据就关连接。
   现象是「TLS 握手成功但响应永远不来」。两个方向本来就是单读/单写，各用各的锁即可。

8. **改设置要重启进程才生效**：面板切「WireGuard 出栈」只写了配置，`start_wg_outbound()`
   却只在进程启动时调用一次，于是 UI 显示「已启用 / 未就绪」而栈根本没起来，
   用户也无从得知原因。现在 `PUT /panel/update-settings` 检测到 `wgOutbound` 变化就
   立刻 stop+start，并把真实结果（`ready` / `status` / `error`）随响应返回，面板据此提示。
   同时 `WgStack::stop()` 改成真正释放资源（`netif_remove` + `close(udp)` + `reset_session`），
   `lwip_init()` 只在进程内首次启动时跑一次 —— 否则重复 start 会每轮多注册一个 netif、
   泄漏一个 socket。实测连续 5 次开/关，fd 稳定在 6、RSS 波动 20 KB。

> 排查顺序：先看 `/<sp>/panel/warp-status`。`session=up` 但 `tx` 狂涨、`rx` 不动
> → 对端已丢包；`tx/rx` 大致平衡但业务不通 → 回头看第 6、7 条。

## 性能实测

测试链路：**本机 curl --proxy → bpb 的 VLESS → WARP 出栈 → GitHub**，
`cloudflare.com/cdn-cgi/trace` 返回 `warp=on` 确认流量确实经过 bpb。服务端每秒采样
`/proc/<pid>/status`。机器为 1 核 / 469 MB。

### 内存随连接数

| 并发连接 | RSS | 匿名内存 | 线程数 | 相对基线 |
|---:|---:|---:|---:|---:|
| 1（基线） | 5688 kB | 1988 kB | 3 | — |
| 3 | 5772 kB | 2072 kB | 6 | +84 kB |
| 9 | 6272 kB | 2572 kB | 15 | +584 kB |
| 17 | 9588 kB | 4032 kB | 27 | +3900 kB |
| 23 | 9248 kB | 3692 kB | 36 | +3560 kB |
| 27 | 9524 kB | 3968 kB | 42 | +3836 kB |
| 43 | 8748 kB | 3192 kB | 66 | +3060 kB |

**每连接约 +120~150 kB，每连接 1.5 个线程**（`Threads ≈ 1.5 × conns + 1.5`，
对应每个 WebSocket 会话的上传/下载两个线程）。斜率**非线性**：1→17 连接时明显上升，
之后稳定在 8.7~9.5 MB —— lwIP 的 pbuf 池与 TCP 控制块首次高并发时扩容，之后复用。

### 内存随下载字节数

单连接下载 GitHub 上 275 MB 的真实文件：

| 阶段 | RSS |
|---|---|
| 下载前 | 5688 kB |
| 已传 14.7 MB | 5772 kB |
| 全程峰值 `VmHWM` | 9396 kB（出现在并发测试期间） |

**斜率接近 0**：14.7 MB 只涨了 84 kB。这是流式转发的正确表现 ——
`session.cpp` 的 `kChunk = 16384` 是固定缓冲，读完即写、写掉即丢，不缓存整份响应。

> 注意：**面板 HTTP 路径不同**。`http/http.cpp` 会把整个响应体拼进 `c.out` 再发
（`out.reserve(res.body.size() + 256)`），所以内存与响应体线性相关。
面板静态文件只有约 130 KB，订阅 JSON 也只有几十 KB，不构成问题；
但如果将来要在这个端口上服务大文件，需要改成分块流式写。

### 并发吞吐

| 场景 | 结果 |
|---|---|
| 20 并发 `generate_204` | 20/20 返回 204，单请求 0.85~3.7 s |
| 10 路同时下载 275 MB 文件 | 10/10 返回 200，合计约 **1.64 MB/s**（单路 64~300 KB/s） |

### 大文件单连接中断（三个根因，已修复）

早期版本里 100 MB 级下载**每个连接都在 3.8~33 MB 处中断**，服务端日志是

    [tunnel] h2 write failed on stream 117
    [tunnel] edge connection lost
    [tunnel] reconnecting in 1s

客户端表现为「下载到一半停了」加「反复短暂停顿」。逐层拆开后是三个独立 bug：

1. **h2 流控把「窗口为 0」当成「窗口还没初始化」。**
   `WINDOW_UPDATE` 和 `write_data` 里都有 `if (w == 0) w = peerInitialWindow_`，
   于是窗口一归零就被补成 4 MB —— 凭空造出对端从未授予的额度。表现是
   `conn=1069613055 sw=0` 这种荒唐数字，边缘最终判定违约并拆连接。
   RFC 7540 §6.9 里 0 就是合法状态，现在只在 map 里查不到时才初始化
   （`find`/`emplace`），并检查 2^31-1 上限。
2. **同一个 stream 发了两次 `END_STREAM`。** 尾部数据帧带了 END_STREAM 之后，
   收尾逻辑又补了一个空 DATA+END_STREAM，边缘直接
   `RST_STREAM PROTOCOL_ERROR (code=1)` 把整条连接带走。两处发送点加了
   `endSent` 守卫，`code=1` 计数从 4 降到 **0**。
3. **中继的等待只盯边缘 socket，不看 origin。** 主循环是
   `srv->poll(timeout); pumpOrigins();`，而 `poll` 只等 Cloudflare 边缘那条
   TCP —— WARP 早就把数据放进 origin socket 了，但我们没被唤醒，要等超时才去读。
   空闲超时是 100 ms，于是每 100 ms 才搬一次 16 KB（≈160 KB/s），
   外加每个协议往返都多 100 ms（一次 TLS 握手因此要 1~2 秒）。
   现在有会话时用 `activePollMs = 2`，完全空闲才退回 `idlePollMs = 100`。

修复后同一份 275 MB 文件的实测（1 核 VPS，链路 WARP → Cloudflare 隧道 → 本地 VLESS）：

| | 修复前 | 修复后 |
|---|---|---|
| 结果 | 31,502,973 字节后 `exit=56` 中断 | **275,096,880 字节完整下完 `exit=0`** |
| 速度 | 97 KB/s | **1.06 MB/s（10.9 倍）** |
| 停顿 | 2~4 秒一跳，最后 24 秒无响应 | 连续完成 |
| CPU（下载中） | 6.6% | 8.8~10.8% |
| CPU（空闲、有会话挂着） | 0.3% | 1.9% |

同一台机器**直接**拉这个文件是 41.8 MB/s，所以隧道这一段仍有 40 倍差距。
再往上要做的不是继续缩短超时，而是把 origin 的 fd 一并放进 poll 集合
（现在是 2 ms 粒度的次优解）。

## 架构

    src/inbound  入栈注册表 + 每协议一个源文件（vless/trojan/shadowsocks/vmess）
    src/inbound/proto  <协议>_ws.cpp：WS 帧编解码、握手、协议帧、双向转发
    src/net      套接字、poll/WSAPoll 封装、HTTPS 客户端（支持 CONNECT 代理）、TLS 流
    src/http     HTTP/1.1 服务（keep-alive、WebSocket 升级）
    src/proxy    会话配置与前向声明；各入栈实现见 src/inbound/proto/*
    src/tunnel   内置 Cloudflare Tunnel 客户端：capnp / HTTP/2 / RPC / 回源 / 监督重连
    src/sub      xray / sing-box / clash / raw / wireguard 订阅生成，WARP 注册
    src/settings JSON 设置存储（原子写）
    src/app      路由、面板接口、DoH、二维码、Telegram
    src/crypto   SHA-224/256、HMAC、HS256 JWT
    src/wg       用户态 WireGuard（Noise IK）
    assets       浏览器面板源文件，构建前由 tools/gen_assets.py 嵌入二进制
    third_party  nlohmann/json、qrcodegen、lwIP
> **入栈协议**：VLESS `/vl`、Trojan `/tr`、Shadowsocks `/ss`、VMess `/<uuid>-vm`，
> 每个协议一个源文件，按 `-DBPB_INBOUNDS` 裁剪；没编进来的路径一律 404。
> 细节（含 VMess 的 AEAD 实现、KDF 推导、early data）见 [INBOUNDS.md](INBOUNDS.md)。


## 测试

见 [TESTS.md](TESTS.md)：编译、冒烟、半关闭请求、双向转发回归、路由重定向、TLS、
WARP 出口（含 `warp=on` 实测）、资源占用、隧道重连、多架构二进制，以及
**入栈协议按编译期裁剪**（每协议一个二进制、面板与订阅跟着裁剪）、
**四协议上传/下载字节数**（本地 sink 计量）、**大文件与限速下不截断**三组回归。

实测摘要（本机 WSL，Xray 26.10.29 与 sing-box 1.14.4 作客户端）：

| 用例 | 结果 |
|---|---|
| VMess：204 / https / 下载 5MB / 20MB / 上传 1MB / 5MB | 全部通过，下载字节精确 |
| VMess：aes-128-gcm / chacha20-poly1305 / WS early data | 三种组合全过 |
| VMess 经真实 Cloudflare 边缘 + WARP 出口 | `warp=on`，204/200，5MB 精确，上传 1MB 精确 |
| Trojan / Shadowsocks / VLESS | 204 / 5MB 下载 / 100KB~5MB 上传字节精确 |
| 大文件：四协议下载 64/256/512MB、上传 64/256MB | 全部逐字节精确（修复前 trojan 64MB 只到 45MB） |
| 限速客户端（2MB/s 与 400KB/s）下载与上传 | 四协议全部精确，慢客户端不被误杀 |
| 单协议二进制（vless/trojan/shadowsocks/vmess） | 各自编译、static、启动行只含自己 |

## CI 与发布（GitHub Actions）

`.github/workflows/build.yml` **只手动触发**（Actions → build → Run workflow），
日常提交不会白跑一遍全矩阵构建；同一分支重复触发不会互相取消
（`cancel-in-progress: false`），避免"再点一次 Run"把正在跑的发布打断。

两个输入：

| 输入 | 说明 |
|---|---|
| `tag` | 必填。全部构建成功后才创建；**若该 tag 已存在则覆盖**（tag 强推到本次 commit，release 里的同名二进制逐个替换） |
| `protocols` | `all` / `vless` / `trojan` / `shadowsocks` / `vmess`。**每个协议各出一个独立二进制**，不是合并进一个 |

协议清单从 `CMakeLists.txt` 的 `set(BPB_ALL_INBOUNDS …)` 读，加协议只改那一行。
产物命名：

    bpb-linux-<arch>-<协议>          amd64 / arm64 / armv7 / 386 / riscv64
    bpb-windows-x86_64-<协议>.exe

`all` = 5 架构 × 每个协议，再加 Windows。每个产物都会自检「编进去的协议是不是只有
预期那一个」—— 启动日志里 `inbounds:` 对不上就整轮失败，避免发出名不副实的二进制。
产物在 **Alpine（musl）** 里构建，所以代码不能依赖 glibc 专有头：`<execinfo.h>`
（`backtrace()`）在 musl 上不存在，`src/util/crash.cpp` 用 `__has_include` 探测缺失时
自动退化成"只打印信号、不打印栈"，不会因此编不过。

**不产出也不发布容器镜像。**

## 许可证

GPL-3.0，与上游一致。面板 HTML/CSS/JS 资源来自上游项目。