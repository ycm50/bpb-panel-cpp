# 测试清单

改动 C++ 源码后按顺序执行。全部可脚本化，不需要 Node.js。

## 1. 编译

    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build

预期：生成 build/bpb，全程不使用 MSVC。

另外验证"单文件可运行"：把 build/bpb（或 bpb.exe）单独拷到空目录直接运行，应当自动创建
`.bpbdata/` 并能在 http://127.0.0.1:8080/securepath/panel 打开面板（面板资源已内嵌，不需要 --assets）。

首次启动后目录结构应为：

    .bpbdata/config.json
    .bpbdata/settings.json
    .bpbdata/favicon.ico
    .bpbdata/assets/{panel,login,error}/index.html

并验证**静态资源是每次请求从磁盘读**（不常驻内存）：

1. 改 `.bpbdata/assets/panel/index.html` 的 `<title>`，**不重启**直接刷新，应立刻生效；
2. 重启进程，改动仍应保留（已存在的文件不会被内嵌副本覆盖）；
3. 把该文件删掉，请求应仍返回 200（自动回退到内嵌副本），不能出现 404。

## 2. 冒烟测试（面板接口 + 订阅）

    docker run -d --name bpb-test -p 18099:8080 -v bpbdata:/data bpb-native:1.0.0
    python3 tests/smoke.py http://127.0.0.1:18099/securepath

预期：13/13 全过（登录、面板设置、8 种订阅、share-settings、DoH、二维码）。

## 2a. 半关闭请求（隧道回源的真实形态）

隧道转发无 body 的 GET 时，会在发完请求后立刻对回源连接 `shutdown(SHUT_WR)`。
服务端必须把已缓冲的完整请求应答完再关闭连接，否则会随机返回 502。

    g++ -std=c++20 -O1 -Isrc tmpscripts/origin_loop.cpp src/tunnel/proxy.cpp -o /tmp/origin_loop -lpthread
    /tmp/origin_loop 127.0.0.1 8080 /securepath/panel 60 6 1

预期：`TOTAL n=60 fails=0 halfclose=1`（最后一个参数为 1 表示发完请求即半关闭）。
把最后一个参数改成 0 则验证普通请求路径。

## 2a. 半关闭请求（隧道回源的真实形态）

隧道转发无 body 的 GET 时，会在发完请求后立刻对回源连接 `shutdown(SHUT_WR)`。
服务端必须把已缓冲的完整请求应答完再关闭连接，否则会随机返回 502。

    g++ -std=c++20 -O1 -Isrc tmpscripts/origin_loop.cpp src/tunnel/proxy.cpp -o /tmp/origin_loop -lpthread
    /tmp/origin_loop 127.0.0.1 8080 /securepath/panel 60 6 1

预期：`TOTAL n=60 fails=0 halfclose=1`（最后一个参数为 1 表示发完请求即半关闭）。
把最后一个参数改成 0 则验证普通请求路径。

## 2c. 双向转发必须两个线程（回归重点）

VLESS over WebSocket 的每个会话用两个线程：client→upstream 与 upstream→client
各自阻塞推进（等价于 cloudflared `stream.Pipe` 的两个 goroutine）。
单线程 poll 调度会让一个方向的慢速拖死另一个方向，表现为大响应约 3 KB 处停住、
15 秒后被边缘 RST。

用真实客户端验证（服务端本机跑即可，不依赖隧道）：

    # 25 次 1 MiB 下载全部成功、20 次 google generate_204 全部 204
    for i in $(seq 25); do curl -so /dev/null -w '%{size_download}\n' \
        --socks5-hostname 127.0.0.1:10970 'https://speed.cloudflare.com/__down?bytes=1048576'; done

预期：25 行全部 `1048576`；任何一行 `0` 都说明双向转发退化成单线程调度。

## 2b. 路由与重定向

- `GET /`、`GET /securepath`、`GET /securepath/` -> 302 到 `/securepath/panel`
- `GET /securepath/panel` -> 200（未设密码）或 302 到 login（已设密码）
- `GET /nope` -> 404，页面显示中文"出错了"与提示信息（不能出现 __ERROR_MESSAGE__ 字样）

## 3. 数据面

VLESS over WebSocket 必须能转原生 TCP。最小验证：

- 用 VLESS 头（版本 0、UUID、cmd=1、端口、atyp=1、IPv4）再拼一个普通 HTTP 请求作为载荷，
  发到 /vl/<任意>，返回帧里应包含 HTTP 响应。

**Trojan 入栈已移除**：`/tr/<任意>` 在 WebSocket 升级前直接返回 404，且不进入数据面。
可用任意 WS 客户端验证：`GET /tr/test` 带 Upgrade 头 -> `HTTP/1.1 404 Not Found`。

注意 WebSocket 路径不在 securePath 下：VLESS 是 `/vl/<随机串>`。

## 4. TLS

    ./build/bpb --port 8443 --data ./.bpbdata --tls-cert cert.pem --tls-key key.pem

- https 访问 /securepath/login -> 200
- 用 http 访问该端口 -> 被拒绝
- wss 上带 VLESS 头 -> 数据面正常

## 5. WARP 出口（两种方式）

### 5a. 侧车容器（整机出网）

    docker run --rm -v "$PWD/data:/data" -v "$PWD/warp:/out" bpb-native:1.0.0 \
      --export-warp /out/wg0.conf --data /data
    docker compose -f docker-compose.warp.yml up -d --build
    docker exec bpb-warp wg show

预期：有 latest handshake，transfer 计数增长；在面板容器内执行 --fetch http://api.ipify.org/
应返回 Cloudflare WARP 的地址。

### 5b. 用户态 WireGuard 出栈（内置，无需 NET_ADMIN）

内置实现位于 `src/wg/`（Noise IK + 传输封装，纯 OpenSSL）与 `src/net/wg_stack`（lwIP）。
账号直接复用 `.bpbdata/settings.json` 里已注册的 `warpAccounts[0]`，**不要重新调用注册接口**
（高频注册会触发 Cloudflare 风控）。

验证顺序：

1. **加密原语自检**（无需网络）

       g++ -std=c++20 -Isrc tmpscripts/wg_crypto_test.cpp src/wg/crypto.cpp -o /tmp/wg_crypto -lcrypto
       /tmp/wg_crypto

   预期：kdf1/2/3 前缀一致、HMAC 与手算一致、AEAD 往返与篡改拒绝、X25519 对称、base64 往返。

2. **握手报文结构**

       g++ -std=c++20 -Isrc tmpscripts/wg_noise_test.cpp src/wg/device.cpp src/wg/crypto.cpp \
           -o /tmp/wg_noise -lcrypto -lws2_32
       /tmp/wg_noise

   预期：init size 148、type==1、sender!=0、mac1 非零、mac2 全零。

3. **真实端点握手**

       g++ -std=c++20 -Isrc tmpscripts/wg_live_test.cpp src/wg/device.cpp src/wg/crypto.cpp \
           -o /tmp/wg_live -lcrypto -lws2_32
       /tmp/wg_live <privB64> <peerPubB64> <localV6/128> 162.159.192.1:2408

   预期：收到 92 字节 type=2 响应、`HANDSHAKE OK`、keepalive 发出后 `tx=32`。

   > 注意：同一 IP 短时间反复握手会被 WARP 限流。两次尝试之间至少间隔 30~60 秒；
   > 出现连续 recv timeout 时先等待再试，不要改代码猜问题。

4. **端到端 TCP**

       g++ -std=c++20 -Isrc -Ithird_party/lwip/src/include -Ithird_party/lwip -Ithird_party \
           tmpscripts/wg_e2e_test.cpp src/net/wg_stack.cpp src/net/lwip_sys.cpp \
           src/wg/device.cpp src/wg/crypto.cpp <build>/liblwip.a \
           -o /tmp/wg_e2e -lcrypto -lws2_32
       /tmp/wg_e2e <privB64> <peerPubB64> <localV6/128>

   预期：`session=up`、TCP 连上 api.ipify.org:80 并取回 HTTP 响应，出口为 WARP 地址。

5. **切换 WireGuard 出栈不需要重启进程**

       # 关
       curl -s -X PUT -H 'Content-Type: application/json' \
         --data-binary '{"wgOutboundEnabled":"false"}' \
         http://127.0.0.1:8080/securepath/panel/update-settings
       # 开
       curl -s -X PUT -H 'Content-Type: application/json' \
         --data-binary '{"wgOutboundEnabled":"true"}' \
         http://127.0.0.1:8080/securepath/panel/update-settings

   预期：响应里的 `body.wgOutbound.ready` 反映真实结果——关闭后 `ready:false` /
   `status:"stopped"`，开启后 `ready:true` / `status:"session=up ..."`。
   **不能**出现「保存成功但 ready 一直是 false」而不给原因的情况。

6. **反复切换不泄漏**（重启路径很容易漏资源）

       PID=$(systemctl show bpb -p MainPID --value)
       for i in 1 2 3 4 5; do
         curl -s -X PUT -H 'Content-Type: application/json' \
           --data-binary '{"wgOutboundEnabled":"false"}' http://127.0.0.1:8080/securepath/panel/update-settings >/dev/null
         curl -s -X PUT -H 'Content-Type: application/json' \
           --data-binary '{"wgOutboundEnabled":"true"}' http://127.0.0.1:8080/securepath/panel/update-settings >/dev/null
         echo "cycle $i: fds=$(ls /proc/$PID/fd | wc -l) rss=$(awk '/VmRSS/{print $2}' /proc/$PID/status)"
       done

   预期：`fds` 稳定在 6 上下、`rss` 波动只有几十 KB。数字逐轮上涨说明
   `WgStack::stop()` 没释放 netif / UDP socket（回归点）。

## 6. 资源占用

    docker stats --no-stream bpb

预期：镜像约 7.5 MB，空载内存 1.5 ~ 2 MB，压测峰值约 4 MB。

## 6b. 隧道重连

隧道断开后必须自动重连并重新注册，不能等到进程重启。
**这些日志默认是关的**（见 §0 日志开关），测试时必须显式打开：

1. 启动带隧道的实例：`bpb --log info --port 8080 --data …`，
   确认出现 `REGISTERED with edge`；
2. 掐断到边缘的 TCP：`ss -K dst <edge-ip> dport = 7844`；
3. 1~30 秒内依次出现 `edge connection lost`（error，任何时候都打）、
   `reconnecting in Ns`（warn，需要 `--log warn` 及以上）、
   `connected to edge`、`REGISTERED with edge`（info）；
4. 重连后面板与 `/vl` 仍返回 200。

同时确认空闲与长连接下 CPU 不空转：`/proc/<pid>/stat` 的 utime+stime 在 6 秒内应为个位数
（有空会话时约 1.9%，见 §6d）。

## 6d. 大文件单连接不中断（回归重点）

三个曾经让下载在 3.8~33 MB 处必断的 bug，任何一个复发都会在这里暴露：

1. 启动带隧道的实例（默认日志级别即可，静默才是正常）；
2. 从外部经隧道拉一个 275 MB 的文件：
   `curl -L -o NUL -w '%{size_download} %{speed_download}\n' <url>`；
3. 预期：**完整下完**，`size_download` 等于文件大小、退出码 0；
   服务端 journal 里**不应出现** `edge connection lost`；
4. 回归特征：卡在某个固定量级后 `curl: (56)`，或服务端出现
   `[tunnel] h2 write failed`。用 `--log trace` 抓帧可看到
   `RST_STREAM … code=1`（END_STREAM 发了两次）或 `sw=0` 却继续往外写
   （窗口被 `peerInitialWindow_` 顶替）。
5. 吞吐参考：1 核 VPS 上约 1 MB/s（修复前 97 KB/s）；若掉到一百多 KB/s，
   说明 `activePollMs` 又被退回接近 `idlePollMs`。

## 0. 日志开关

默认 **error** 级：健康运行时 stderr 一个字节都不输出。

1. `bpb --port 18099 --data /tmp/x` 起 3 秒后杀掉，
   `stderr` 必须是 **0 字节**（面板资源释放等提示都在 info 级）；
2. `--log info` 应打印 2 行：`[assets] panel extracted`、`listening on …`；
3. `--log trace` 额外打印 `[h2 tx]/[h2 rx]` 每帧日志，
   等价于旧的 `BPB_TUNNEL_TRACE=1`；
4. `--log bogus` 退出码 2 并提示可选值；
5. `BPB_LOG=debug` 与 `--log debug` 等效，命令行优先；
6. **隧道域名不在启动日志里**：只有 `install.sh` 结尾打印「隧道域名 : xxx」。

## 6c. 隧道域名（ingress 配置）

命名隧道的公网域名**不在 token 里**（token 只有 `{"a","t","s"}`），
也不能问 REST 接口——`GET /accounts/<acct>/cfd_tunnel/<uuid>` 用 token 模式的凭据调用
只会返回 `9106 Missing X-Auth-Key, X-Auth-Email or Authorization headers`。
域名只能从边缘推送到控制流的 ingress 配置里取。

1. **解析器单测**（无需网络，纯函数）

       g++ -std=c++20 -O1 -Isrc -Ithird_party tmpscripts/test_ingress.cpp -o /tmp/test_ingress
       /tmp/test_ingress

   预期：`--- all passed (0)`，覆盖真实推送体、通配符 `*.x.com` 不算可拨号域名、
   只有 catch-all 规则时为空、以及 7 种畸形输入不抛异常也不产出域名。

2. **真实边缘**：把 `cfTunnel.token` 填成命名隧道 token 后启动，日志应依次出现

       [tunnel] REGISTERED with edge
       [tunnel] ingress hostnames: <你的域名>
       [cf-tunnel] mainDomain: "localhost" -> "<你的域名>" (ingress)

   `GET /<sp>/panel/tunnel-status` 里 `hostnames` 为该隧道全部 ingress 主机名，
   `hostname`/`url` 是实际采用的那个，`mainDomain` 是订阅当前使用的域名。

   > 调试时设 `BPB_TUNNEL_TRACE=1` 可打印原始推送体；
   > 若 `config body (0 bytes)` 说明在 HEADERS 帧就提前确认了配置流（回归点）。

3. **订阅必须跟着变**：同一个实例上

       curl -s "http://127.0.0.1:<port>/<sp>/sub/normal?app=xray"     | grep -c "<你的域名>"
       curl -s "http://127.0.0.1:<port>/<sp>/sub/normal?app=clash"    | grep -c "<你的域名>"
       curl -s "http://127.0.0.1:<port>/<sp>/sub/normal?app=sing-box" | grep -c "<你的域名>"
       curl -s "http://127.0.0.1:<port>/<sp>/sub/raw?app=xray" | base64 -d | grep -c "<你的域名>"

   预期：全部非 0。（`warp`/`warp-pro` 系列拨的是 WARP 端点，与 `mainDomain` 无关，
   命中 0 是正常的。）

4. **不抢手工域名**：把 `customDomain` 或手工改过的 `mainDomain` 设成别的值后重启，
   预期 `mainDomain` 保持手工值，不被打回 ingress 域名。

5. **休眠 / 唤醒状态**：

   - `POST /<sp>/panel/tunnel-sleep` 之后立刻查 status，`running` 必须是 `false`
     （旧实现要等监督线程的 `run()` 返回才清，期间一直显示在跑）；
   - `POST /<sp>/panel/tunnel-wake` 返回 `running:true`，随后 status 的
     `connected/registered` 翻成 `true`；
   - 唤醒响应里不能把 `hostname`/`url` 清空（ingress 域名是隧道属性，不是连接的属性）。

## 8. 安装脚本

脚本必须做到：**按架构选二进制、校验和、装服务、开隧道、打印域名**，
并且 `--port` 同时决定面板端口和隧道回源端口。

1. **语法与参数校验**（不需网络）

       sh -n install.sh && echo OK
       sh install.sh --help
       sh install.sh --port abc        # 必须报错：--port must be a number
       sh install.sh --nope           # 必须报错：unknown option

   非 root 执行必须被拒绝（`su nobody -s /bin/sh -c 'sh install.sh'`）。

2. **release 未构建时的提示**（tag 存在但无资产）

       sh install.sh --tag v1.0.0

   预期：不只是一行 curl 404，而是明确提示「本仓库用**手动** workflow 发布，
   光有 tag 不够，需要 Actions → build → Run workflow」。

3. **完整流程**（用本地二进制，跳过下载）

       sh install.sh --local ./bpb --port 9099 --data /root/.bpbtest

   预期依次输出：架构识别 → 安装二进制 → 写 `settings.json`（`originPort` 必须是 9099）
   → 启动服务 → **打印公网域名**。之后：

       curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:9099/securepath/panel   # 200
       curl -s -o /dev/null -w '%{http_code}\n' https://<打印的域名>/securepath/panel     # 200

4. **实例隔离（回归重点）**：`--data` 非默认值时必须是独立实例。
   在上面测试运行期间，**生产实例必须不受影响**：

       grep ExecStart /etc/systemd/system/bpb.service   # 仍是原来的端口/数据目录
       ss -tln | grep 8080                              # 生产端口仍在监听

   若 `--data /root/.bpbtest --port 9099` 覆盖了 `bpb.service`，说明服务名没有按
   数据目录区分——测试会把正式面板换到别的端口上。

5. **卸载**：`sh install.sh --uninstall --data /root/.bpbtest`，
   预期 service 被停用删除、二进制被移除、**数据目录保留**。

## 7. 多架构二进制

CI 会为 amd64 / arm64 / armv7 / 386 / riscv64 各产出一个静态二进制。本地验证某一架构可执行：

    docker run --rm -v "$PWD:/w" -w /w --platform linux/arm/v7 alpine:3.22 ./bpb-linux-armv7 --help

（需要宿主机装好 qemu-user 的 binfmt，或在 CI 里跑。）

## 0b. 入栈协议按编译期裁剪（回归重点）

协议清单是**编译期**决定的，没编进去的协议不能被编译、不能被分发、不能出现在面板和订阅里。

1. **只编一个协议**：
   `cmake -S . -B /tmp/one -DBPB_INBOUNDS=vless` → 配置期必须打印
   `-- bpb inbounds: vless`；`/tmp/one/bpb --log info` 的启动行必须以
   `inbounds: vless` 结尾（多一个协议都不对）。
2. **未选中的协议不参与编译**：构建日志里不应出现
   `trojan_ws.cpp` / `shadowsocks_ws.cpp` 这两个翻译单元。
3. **全协议**：`-DBPB_INBOUNDS=all` → `inbounds: vless,trojan,shadowsocks,vmess`。
4. **非法协议名**：`-DBPB_INBOUNDS=nope` 必须配置期直接 FATAL_ERROR 并列出可用协议。
5. **路径分发**：编入 vless 的二进制访问 `/tr`、`/ss` 都是 404；
   编入 all 时 `/vl` `/tr` `/ss` 都能升级成 WebSocket。
6. **面板裁剪**：`GET /<sp>/panel/settings` 的 `body.inbounds` 与实际编入一致；
   `PUT /<sp>/panel/update-settings` 提交 `{"protocols":"<没编进去的协议>"}` 返回 400，
   提交混合列表时没编进去的项被静默剔除。
7. **订阅裁剪**：`sub::get_protocols()` 与协议表求交集；把一个没编进去的协议写进
   settings.json，生成出来的订阅里不应出现它。

## 0c. 每协议一个独立二进制（发布前自查）

用官方 Xray 客户端（outbound 分别配 vless / trojan / shadowsocks / vmess，
streamSettings.network=ws、security=none、路径对 /vl /tr /ss /<uuid>-vm）各跑一次：

    curl -x socks5h://127.0.0.1:<port> -o NUL -w '%{http_code} %{size_download}\n' https://example.com/

预期四个都是 200；服务端 --log debug 能看到对应的 [trojan] host:port / [ss] host:port /
[vmess] host:port。Shadowsocks 用 method=aes-256-gcm、密码填面板 UUID；VMess 用
alterId 0 + security auto。sing-box 客户端同样要过（alter_id 0，transport ws，
可选 max_early_data 2048 + early_data_header_name）。

**矩阵自查（本地可完整复现 CI 的断言）**：对 vless / trojan / shadowsocks / vmess 各做一次
-DBPB_INBOUNDS=<proto> 的独立构建，配置期必须打印 -- bpb inbounds: <proto>，二进制必须
static，启动行必须恰好是 inbounds: <proto>。脚本：tmpscripts/matrix.sh，期望末行
MATRIX-RESULT fail=0。实测四个都是 OK（9.1MB 左右，static=1）。

**必须连 musl 一起验**：CI 的静态产物在 alpine:3.22（musl）里编，只在本机 glibc 上
过编译是不够的。本地等价做法是用 alpine-minirootfs 建 chroot（不需要 docker）：

    curl -fsSL -o /tmp/alpine.tgz https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/alpine-minirootfs-3.22.1-x86_64.tar.gz
    mkdir -p /tmp/alpine && tar xzf /tmp/alpine.tgz -C /tmp/alpine && cp /etc/resolv.conf /tmp/alpine/etc/
    chroot /tmp/alpine /bin/sh -c 'apk add --no-cache g++ musl-dev cmake samurai openssl-dev openssl-libs-static zlib-dev zlib-static'

然后把仓库挂进 chroot 做四个协议的 -DBPB_STATIC=ON 构建，最后照 CI 那两步自检跑一遍
（--help 能跑 + 启动行 inbounds: 恰好等于预期协议）。脚本：tmpscripts/alpine_repro.sh 与
tmpscripts/alpine_verify.sh，期望末行 BUILD_OK ×4 与 VERIFY-RESULT fail=0。
工作流里那段 sh -c 自检本身也可以脱离 docker 复现：tmpscripts/sim_step.sh 配
tmpscripts/fakedocker/docker（一个只做 -v / -w 映射的假 docker），正例返回 0，
把日志换成 trojan 或 "vless,trojan" 必须返回 1。

## 0d. 崩溃必须留下栈

`src/util/crash.cpp` 装了 SIGSEGV/SIGABRT 处理器。故意触发一次致命信号后，
journal 里应出现 `[bpb] fatal signal N -- backtrace:` 与若干帧地址，而不是只有一行
`free(): double free detected`。二进制需要 `-rdynamic`（CMake 已加）。

注意 `backtrace()` 是 glibc 的东西，**musl 没有** `<execinfo.h>`，Alpine 仓库里也没有
libexecinfo。所以这里用 `__has_include(<execinfo.h>)` 探测：有就打印栈，没有就退化成
`[bpb] fatal signal 11 -- no backtrace support in this libc`（信号本身照打，进程照样按
默认动作退出）。CI 的静态产物正好是 musl 构建，硬写 `#include <execinfo.h>` 会让
**全部 20 个 Linux 任务** 编译失败（实测 run 41361090373）。

实测：
- glibc 构建（WSL，`kill -SEGV`）：打印 7 帧，含 `bpb::http::Server::run`。
- musl 构建（Alpine chroot，一样打信号）：只打印信号行 + 无栈提示，不崩第二次。

## 0e. VMess 入栈（回归重点）

VMess 与其它协议不同：凭据出现在 WS 路径里（`/<uuid>-vm`），且服务端要自己实现
AEAD 头、认证长度、SHAKE128 掩码长度、响应头与终止 chunk。下面每一条都跑过一次。

准备：WSL 里跑静态构建的 bpb（--data 目录里放 config.json 的 vlUUID 与
settings.json 的 "protocols":"vless,vmess"），Xray 作客户端：

    # outbounds[0] = vmess，streamSettings = {"network":"ws","wsSettings":{"path":"/<uuid>-vm"}}
    xray -c tmpscripts/vmtest/xray-gcm.json

1. **基本连通**：`curl --socks5-hostname 127.0.0.1:10809 http://cp.cloudflare.com/generate_204`
   得 204；`https://www.cloudflare.com/cdn-cgi/trace` 得 200。
2. **下载不截断**：`http://speed.cloudflare.com/__down?bytes=5000000` 的 size_download 必须是
   5000000；`bytes=20000000` 必须是 20000000。少一个字节都算失败（早期版本只到 3.9MB，
   原因是一个方向结束就拆了整个会话）。
3. **上传不截断**：`POST --data-binary @/tmp/up5m.bin http://speed.cloudflare.com/__up`
   得 200，服务端日志 up=5243064（含 HTTP 头）。
4. **两种加密**：users[].security 分别用 aes-128-gcm（日志 security=3）与
   chacha20-poly1305（security=4），上面 1–3 全过。
5. **WS early data**：wsSettings 加 "maxEarlyData":2048 与
   "earlyDataHeaderName":"Sec-WebSocket-Protocol"，路径写 `/<uuid>-vm?ed=2048`，再跑 1–3。
   服务端不先尝试握手就无法完成（客户端把整头塞在请求头里然后等响应），
   --log trace 应看到 `[vmess] upgrade path=... early=273` 紧跟 `[vmess] <host>:<port> security=3`。
6. **对照真实客户端**：Xray 26.10.29 全程零错误；客户端日志不应出现
   failed to read response header / failed to read header。
7. **路径裁剪**：访问 `/<uuid>-vm` 之外的段（例如 /vm）必须 404；
   path_list() 里 VMess 显示为 `/<uuid>-vm`。
8. **订阅**：raw 订阅里出现 vmess:// + base64(JSON)，解出来 net=ws、path=/<uuid>-vm、
   aid=0、scy=auto、type=none；TLS 端口上 tls=tls 且带 sni/alpn/fp。

一键复跑（tmpscripts 不入仓库）：

    wsl -e bash /mnt/a/Downloads/bpb-panel-cpp/tmpscripts/vmtest/runall.sh

依次跑 aes-gcm / chacha / early-data / vless 回归四套，末行打印 ALL-DONE。

## 0f. 上传方向必须用本地 sink 计数（四协议通用）

境外接口（speed.cloudflare.com/__up）不稳定，用它判断上传是否截断会得到假失败。
正确的做法是起一个本地 HTTP sink，由它打印实际收到的字节数：

    python3 tmpscripts/vmtest/sink.py          # 监听 127.0.0.1:19000，打印 "got N/M bytes"
    curl --socks5-hostname 127.0.0.1:10809 -X POST --data-binary @1mb.bin http://127.0.0.1:19000/up

对 trojan / shadowsocks / vmess / vless 各跑 100 KB 与 1 MB，期望
`got 102400/102400` 与 `got 1048576/1048576`。

**第 20 轮修掉的真实缺陷**：trojan 的 `relay()` 原本在握手后**新建**一个 WsIn，
把解析头部时已经读进 `raw` 的「半张 websocket 帧」丢掉了 —— 那半帧再也拼不完整，
请求体永远到不了 origin（GET 因为只有一个帧所以看不出来）。现在 `relay()` 复用同一个
WsIn，与 shadowsocks 的写法一致。

9. **sing-box 互操作**（第二套部署写法，见 goal 第 7 项）：socks 入口 + vmess 出站，
   `alter_id:0`、`security:"auto"`、`transport:{type:"ws",max_early_data:2048,early_data_header_name:"Sec-WebSocket-Protocol"}`。
   跑上面 1–3 全部通过；`--log debug` 里能看到 option=`0x05`（sing-box 不加全局填充，
   xray 是 `0x0d`），两种都正常。

10. **VMess 走 WARP 出口**：注册 WARP 账号（`POST /<sp>/panel/update-warp`）→
    `proxySettings.wgOutbound.enabled=true` 重启，日志要有 `wireguard outbound enabled`，
    `/<sp>/panel/warp-status` 的 `status` 里要有 `session=up`；再经 VMess 抓
    `https://www.cloudflare.com/cdn-cgi/trace`，必须看到 `warp=on` 与 Cloudflare 的 IP。
    这覆盖的是 `ws_transport.h` 的 `BPB_WSX_WG_STACK` 分支（lwIP 内联 WARP）。
11. **vmess-only 二进制的面板裁剪**：`inbounds` 只列 vmess；`PUT protocols=vless`
    必须 400 并提示「可用： vmess」。
