# bpb-panel-cpp

[BPB Panel](https://github.com/bia-pain-bache/BPB-Worker-Panel) 的 **C++20 服务端重写版**。

上游是跑在 Cloudflare Workers 上的面板；本项目保留它的订阅格式与面板接口，
把运行时换成可移植的 HTTP/WebSocket 服务 + 原生 TCP 数据面，外加一个自研的
Cloudflare Tunnel 客户端。**服务端没有任何 JavaScript/TypeScript**，产物是
**单个静态二进制**，面板 HTML/CSS/JS 已内嵌其中。

| 指标 | 实测值 |
|---|---|
| 二进制（Linux 静态） | 约 9 MB（替换了 40 MB 的 cloudflared） |
| 常驻内存 | **6.5 MB**（压力下 9.5 MB，峰值 11.6 MB） |
| 空闲 CPU | **0.02%** 单核 |
| 满速 1 MB/s 传输 | 约 44% 单核（TLS 加解密开销） |

## 目录

- [功能](#功能)
- [分支说明](#分支说明)
- [快速开始](#快速开始)
- [从源码构建](#从源码构建)
- [命令行](#命令行)
- [接口](#接口)
- [Cloudflare Tunnel](#cloudflare-tunnel)
- [数据面：VLESS over WebSocket](#数据面vless-over-websocket)
- [WARP 出口](#warp-出口)
- [架构](#架构)
- [测试](#测试)
- [许可证](#许可证)

## 分支说明

| 分支 | WARP 出栈 | 特点 |
|---|---|---|
| `main` | 独立进程 `warp-rust`（Rust，自带用户态栈） | bpb 负责渲染配置、监督生命周期，经本地 SOCKS5 转发 |
| `warp-built-in` | 进程内 `src/wg` + lwIP | 单二进制、零外部依赖、内存更省 |

两个分支的**面板、订阅、隧道功能完全一致**，差异只在 WARP 数据面。

## 功能

- **VLESS over WebSocket** 转原生 TCP，URL 布局与上游一致（`/vl/...`）；
  Trojan 入栈已移除，`/tr/` 直接 404
- **订阅**：Xray（normal / fragment / warp / warp-pro）、sing-box、Clash/Mihomo、
  raw 链接、WireGuard 与 Amnezia 的 `.conf` 打包
- **面板**：沿用上游界面并中文化（登录、设置、重置、my-ip、WARP 刷新、订阅、二维码）
- **DoH 反向代理**、**PNG 二维码**、**设置导入导出**
- **可选内置 TLS**（`--tls-cert` / `--tls-key`），https 与 wss 都支持；也可交给 Caddy 终止
- **内置 Cloudflare Tunnel 客户端**：不需要 cloudflared，注册、转发、断线重连全在进程内
- **WARP 出口**：两种实现，见 [WARP 出口](#warp-出口) ——
  独立进程 `warp-rust`（`main` 分支）或**内置用户态 WireGuard**
  （`warp-built-in` 分支，Noise IK + lwIP，无需特权）
- **面板内注册 WARP 账号**：默认 **dry run** —— 只构造并打印请求体、
  返回合成账号，**不访问 Cloudflare**、不写账号池
- **隧道按需唤醒 / 休眠**：临时隧道不常驻，用的时候一句话拉起；
  注册到的域名会**自动同步成订阅主域名**，不再需要手改 `mainDomain`
- **Telegram 机器人**的绑定 / 解绑 / webhook

## 快速开始

    docker build -t bpb-native:1.0.0 .
    docker run -d --name bpb -p 8080:8080 -v bpb-data:/data bpb-native:1.0.0

打开 <http://localhost:8080/securepath/panel>。

首次启动会生成 `data/config.json`（含随机 VLESS UUID）与 `data/settings.json`。

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
    ./build/bpb --host 0.0.0.0 --port 8080 --data ./data

依赖：GCC/Clang（支持 C++20）、OpenSSL、zlib。CMake 会**主动拒绝 MSVC**。

不依赖 CMake 的一次性静态编译（与 CI 一致）：

    g++ -O2 -std=c++20 -static -Isrc -Ithird_party \
        src/*.cpp src/*/*.cpp third_party/qrcodegen.cpp \
        -o bpb -lssl -lcrypto -lz -lpthread

### Windows（MSYS2 UCRT64）

    cmake -S . -B build-win -G Ninja -DCMAKE_CXX_COMPILER=A:/msys64/ucrt64/bin/g++.exe
    cmake --build build-win

## 命令行

| 参数 | 说明 |
|---|---|
| `--host <ip>` | 监听地址，默认 `0.0.0.0` |
| `--port <n>` | 监听端口，默认 `8080` |
| `--data <dir>` | 数据目录，默认 `./data`，不存在会自动创建 |
| `--assets <dir>` | 临时替换内嵌面板资源（正常不需要） |
| `--tls-cert` / `--tls-key` | 启用 HTTPS / wss |
| `--export-warp <file>` | 导出侧车用的 `wg0.conf` |
| `--fetch <url>` | 出网诊断 |

面板资源已编译进二进制，**单独一个可执行文件就能跑**。

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
| `/<sp>/panel/tunnel-status` / `tunnel-wake` / `tunnel-sleep` | 隧道的查看 / 唤醒 / 休眠 |
| `/<sp>/panel/update-warp`、`/<sp>/telegram/{setup,remove,webhook}` | WARP 账号、Telegram |
| `/vl/<random>` | VLESS over WebSocket |

`<sp>` 是安全路径，默认 `securepath`。上游的 Cloudflare 专属功能
（Worker 自部署、KV 用量统计、面板自更新）没有实现，面板里已隐藏。

## Cloudflare Tunnel

面板里打开隧道开关后，进程会自己注册到 Cloudflare 边缘，把公网请求转发回本机
监听端口，不再需要 40 MB 的 cloudflared。

**两种取凭据的方式**：

- `cfTunnel.token` 填了值 → 走**命名隧道**，域名由你自己的 Cloudflare 账号决定
- `cfTunnel.token` 为**空** → 自动注册**临时隧道**（`POST api.trycloudflare.com/tunnel`），
  拿到 `{id, account_tag, secret, hostname}`，拼成同样的 `{"a","t","s"}` token 后照常连接。
  凭据落在 `data/tunnel-quick.json`，**重启复用同一个域名**，不会每次都注册新的

**域名自动同步**：临时隧道注册成功时，把 `config.json` 的 `mainDomain` 改写为该域名并落盘
（日志会打印旧值 → 新值）。订阅是按请求实时渲染的，所以下一次拉订阅就指向可用地址。
这一点很关键——曾经因为 `mainDomain` 还停在一条已经死掉的命名隧道上，
隧道本身健康、面板却发出一堆连不上的配置。

**按需唤醒**：`tunnel-sleep` 关掉连接、面板回到待机；`tunnel-wake` 再拉起，
不常驻一个边缘连接。

> **已知限制**：`data/tunnel-quick.json` 里的凭据如果已在 Cloudflare 侧失效
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

## 数据面：VLESS over WebSocket

每个 WebSocket 会话用**两个线程**分别搬运两个方向，等价于 cloudflared
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
| `warp-rust` | `main` | 外部独立进程；bpb 渲染 `warp-rust.toml`、监督生命周期，数据经本地 SOCKS5（`127.0.0.1:11080`）转发 |
| 内置 `src/wg` + lwIP | `warp-built-in` | 进程内用户态 TCP/IP 栈直连 WireGuard，不需要外部程序也不需要 `NET_ADMIN` |

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
| `warp-rust`（`main`） | 常驻约 **7.4 MB**（bpb 2.4 MB + warp-rust 5.2 MB），同样 10 次连续成功 |

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

> 排查顺序：先看 `/<sp>/panel/warp-status`。`session=up` 但 `tx` 狂涨、`rx` 不动
> → 对端已丢包；`tx/rx` 大致平衡但业务不通 → 回头看第 6、7 条。

## 架构

    src/net      套接字、poll/WSAPoll 封装、HTTPS 客户端（支持 CONNECT 代理）、TLS 流
    src/http     HTTP/1.1 服务（keep-alive、WebSocket 升级）
    src/proxy    VLESS over WebSocket -> 原生 TCP 中继（双向双线程）
    src/tunnel   内置 Cloudflare Tunnel 客户端：capnp / HTTP/2 / RPC / 回源 / 监督重连
    src/sub      xray / sing-box / clash / raw / wireguard 订阅生成，WARP 注册
    src/settings JSON 设置存储（原子写）
    src/app      路由、面板接口、DoH、二维码、Telegram
    src/crypto   SHA-224/256、HMAC、HS256 JWT
    src/wg       用户态 WireGuard（Noise IK）
    assets       浏览器面板源文件，构建前由 tools/gen_assets.py 嵌入二进制
    third_party  nlohmann/json、qrcodegen、lwIP

## 测试

见 [TESTS.md](TESTS.md)。涵盖编译、冒烟、半关闭请求、双向转发回归、
路由重定向、TLS、WARP、资源占用、隧道重连与多架构二进制。

## CI

`.github/workflows/build.yml`：**只有手动触发**（Actions → build → Run workflow），
没有 push / PR 自动构建。

- 手动运行时填两项：`branch`（要编译的分支，默认 main；也可填 tag / 提交 SHA，
  留空则用触发这次运行时所选的分支）与 `tag`（发布 tag 号）。页面右上角的
  "Use workflow from" 只决定跑哪份 workflow 文件，checkout 哪份代码看 `branch`。
- **构建**：5 个架构的 Linux 静态二进制（amd64 / arm64 / armv7 / 386 / riscv64）
  与 Windows x86_64，逐个校验产物可执行。**不产出也不发布容器镜像。**
- **preflight**：先解析 `branch` 的提交，并校验 tag 号格式合法、仓库里还没有同名 tag
  （打错字不必等 20 分钟编译完才发现）。
- **release**：必须等全部架构构建**成功**之后才执行，用输入的 tag 创建 tag 与
  Release —— 任一架构失败，仓库里不会多出 tag。
- **产物**：`bpb` 五个架构（amd64 / arm64 / armv7 / 386 / riscv64）+ Windows x86_64；
  `warp-rust`（WARP 出栈子进程）**只有 amd64 / arm64**。
- **warp-rust 不由 CI 编译**：打包时从 `Shannon-x/cf-warp-rust` 的 release 取
  `x86_64-unknown-linux-musl` 与 `aarch64-unknown-linux-musl` 两个静态包，
  先用上游的 `.sha256` 校验、再解出二进制跟 bpb 一起发，并附 `warp-rust-source.txt`
  记录来源 tag 与校验和。可选输入 `warp_tag` 可指定上游版本（留空 = 最新 release）。
  原因：它的 TLS 栈由 rustls 拉进 `aws-lc-sys`（reqwest 0.13 的 `rustls` feature 就是
  `__rustls-aws-lc-rs`）与 `ring` 0.17，两者都是「Rust 包 C 库」；AWS-LC 官方活跃测试
  的 Linux 平台只有 aarch64 / x86-64（arm32 / x86 / risc-v64 属 best-effort），
  pregenerated bindings 也只覆盖 aarch64 / x86-64 的 gnu 与 musl —— 上游自己同样只出
  这两个 musl 包。其余架构缺 `warp-rust` 时面板把 WARP 出栈标记为不可用，其它功能不受影响。
- **工具链**：C++ 用 `alpine:3.22`（五个架构都已验证能编出静态 musl 二进制）。

## 许可证

GPL-3.0，与上游一致。面板 HTML/CSS/JS 资源来自上游项目。
