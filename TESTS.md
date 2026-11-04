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

    docker run -d --name bpb-test -p 18099:8080 -v bpbdata:/data bpb-native:1.0.2
    python3 tests/smoke.py http://127.0.0.1:18099/securepath

预期：13/13 全过（登录、面板设置、8 种订阅、share-settings、DoH、二维码）。

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

    docker run --rm -v "$PWD/data:/data" -v "$PWD/warp:/out" bpb-native:1.0.2 \
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

## 6e. 大文件不经隧道也必须完整（非阻塞写回归，四协议）

§6d 测的是隧道；这一节测的是入栈本身。**非阻塞 socket 上 `send_all` 把
`EAGAIN` 当成断连**，只在「传输量 > 内核缓冲」且「客户端比源慢」时才暴露，
5MB 的小测试永远是绿的。第 21 轮实测 trojan 与 shadowsocks 就是这样断的
（trojan 64MB 下到 45,632,373 字节），vless/vmess 因为早有等待循环所以正常。

环境：本地 bpb（`-DBPB_INBOUNDS=all`，`protocols` 四协议全开）+ 本地 HTTP origin
（`python3 -m http.server`）+ 本地 sink 计数上传端口。脚本：`tmpscripts/big_transfer.sh`。

1. 不限速：64MB / 256MB / 512MB 下载，64MB / 256MB 上传；
2. 预期 `size_download` **精确等于**文件字节数，上传方向 sink 打印 `got N/N` 相等；
3. 再跑限速组（这一步才是真正的探针）：
   `--limit-rate 2000k` 下载 64MB（`tmpscripts/throttle_repro.sh`），
   `--limit-rate 400k` 下载 16MB 与上传 16MB（`tmpscripts/harsh_throttle.sh`、
   `tmpscripts/up_throttle.sh`）；
4. 失败特征：`curl` 仍返回 200 但 `size_download` 明显偏小（下载），
   或返回 000 且 sink 的 `got` 小于 `content-length`（上传）；
5. 服务端 `--log debug` 应看到 `session end: up=… down=… reason=upstream closed`，
   且 `down` 等于文件大小 + 少量协议开销（vmess 每 chunk 有 16 字节 tag）；
6. sing-box 1.14.4 也要过一遍（`tmpscripts/singbox_dl.sh`，含 early data 与不带）。

判定标准：**任何协议、任何限速下，字节数都必须精确**；对端真死（TCP 零窗口）时
应当在约 60 秒后放弃，而不是立刻断或永远挂着。

上传方向还要单独压两边（脚本：`tmpscripts/upload_slow_origin2.sh`、
`tmpscripts/up_throttle.sh`）：

1. **客户端快、origin 慢**：origin 每读 64KB 睡 0.2s（≈300KB/s），上传 8MB 要 25 秒，
   期间发送队列一直是满的。四协议 sink 都必须 `8388608/8388608`。
2. **客户端慢**：`curl --limit-rate 400k` 上传 16MB，sink 同样必须精确。
3. **半关闭探针（`tmpscripts/upload_halfclose.sh`）不要当成回归项**：客户端
   `shutdown(SHUT_WR)` 之后确实收不到 origin 的回复，但 **xray 服务端行为一样**
   （`tmpscripts/ref_xray_halfclose.sh` 可复核），属于 WS 的固有语义，不是缺陷。
   要验上传完整性就看 sink 的字节数，不要看这个探针的响应。

### 经 Cloudflare 边缘的上传（真实公网路径）

前面几节都走本机直连，覆盖不到隧道。这一节补上「curl → 公网 → CF 边缘 → bpb
quick tunnel → origin」：

准备（脚本 `tmpscripts/edge_repeat.sh`）：`settings.json` 里把 `cfTunnel.enabled`
打开、`originPort` 指到 bpb 自己的 `--port`；起来后用日志里的
`https://xxx.trycloudflare.com` 生成 xray 客户端（`security: tls` + `tlsSettings.
serverName` 用该域名，`wsSettings.headers.Host` 同域名）；origin 用本地 sink 计字节。

1. 5MB 上传重复 N 次，每次必须 `sink 5242880/5242880`，状态码 200；
2. 判定失败的特征：curl 报 `code=100`（说明 1xx 被当成最终响应）、sink 字节数
   明显偏小、或日志出现 `origin closed before response head`；
3. 下载方向同时验一遍 `speed.cloudflare.com/__down?bytes=5000000` 必须 `5000000`；
4. `RST_STREAM code=8`（CANCEL）是正常收尾，**不要**当成失败；
5. WARP 出口在本机 WSL 上握手不通（`engage.cloudflareclient.com` 只解析出 IPv6，
   WSL 无 v6 路由）。这不是代码问题：换成 IPv4 endpoint 也 `tx=0 rx=0`，
   属于当前环境限制，不纳入回归判定。

## 7. 数据面空转 / 泄漏回归（回归重点）

WS 会话建立后空闲会 100% 烧一个核；「升级成功但不发 VLESS 头」的会话还会永久占住两个
线程和一个 fd。都在 `src/inbound/proto/vless_ws.cpp`：

1. `Outbound::read()` 以前 `recv()` 拿到 `EAGAIN` 就当「没数据」立刻返回 0，调用方那句
   "100 ms 切片"形同虚设，下载线程于是 `recv()/EAGAIN` 空转（实测一核 97.5%）；现在按
   `timeout_ms` 真的 `poll()`；
2. `read_frame()` 增加 `wait_ms`，去掉调用方补的 1 ms `sleep`（每会话每秒 1000 次唤醒）；
3. 握手 30 秒超时（`kHandshakeTimeoutMs`）+ `SO_KEEPALIVE`，哑连接不再占线程。

脚本 `tmpscripts/regress_ws.py`（纯 python3，无第三方库）+ 启动器
`tmpscripts/run_regress_ws.ps1`（起 bpb、起 `python -m http.server` 源站、跑脚本、收尾杀进程）：

    # build/bpb.exe，18400/18401，25 次 1 MiB，8 并发，空闲 8 s，35 s 线程回落
    pwsh -File tmpscripts/run_regress_ws.ps1

    # 基线对比（修复前的二进制：07、09 必须红）
    pwsh -File tmpscripts/run_regress_ws.ps1 -Exe tmpscripts/bpb_old.exe \
        -Port 18402 -HttpPort 18403 -Label old

    # Linux 上手工跑（自备源站）
    python3 -m http.server 18401 --bind 127.0.0.1 --directory tmpscripts/origin &
    python3 tmpscripts/regress_ws.py --port 18400 --http-port 18401 \
        --data .bpbdata --pid <bpb pid>

**端口别用 18000/18099**：`set_reuseaddr()` 在 Windows 上允许重复 bind，端口被别的实例占着
时测试会静默打到别人的服务上。启动器先用
`(Get-CimInstance Win32_Process -Filter "ProcessId=<pid>").CommandLine` 核对自己传的
`--port`/`--data`，再核对监听 socket 的 owner pid 就是该进程，不符直接 abort。

**就绪检查必须发完整 HTTP 请求**（脚本里的 `wait_http()`）：只 `connect()` 再 `close()`
在修复前会踩到 HTTP 层的 busy-loop（`POLLHUP` 没被当成断连，那个 fd 永远留在 poll 集合里，
之后一直烧一核），而且它会把后面所有 CPU 采样污染成 ~97%。那个 busy-loop 本轮已经修掉
（`POLLHUP/POLLNVAL` 按断连处理，单独验收见 §9c），但就绪检查依然应该发完整请求：
它和真实客户端的形态一致，也才能在源站侧断言“确实取到东西”。

预期（实测，25 次 / 8 并发）：

    ID   TEST                                 RES   DETAIL
    01   origin sanity                        PASS  1048576 bytes sha=d824bde2acff
    02   sequential 25x 1MiB                  PASS  25/25 complete, 26214400 bytes, slowest 92 ms
    03   concurrent 8x 1MiB                   PASS  8/8 streams complete
    04a  half-close: session ends             PASS  closed after 0.00s, 2 wire bytes, 2 frames
    04b  half-close: full response            XFAIL 0/1048576 bytes（WS 语义，见第 4 条）
    05   unknown ws path 404                  PASS  /tr/x -> 404, /ss/x -> 404
    06a  wrong uuid: no hang                  PASS  session ended after 0.00s (close frame)
    06b  wrong uuid: no data                  PASS  0 payload bytes (close frame)（见第 6 条 / §9d）
    07   idle cpu, 1 session                  PASS  0.00% of one core over 8.0s idle (limit 5.0%)
    08   idle cpu, 20 silent ws               PASS  1.34% of one core over 8.1s, threads 5 -> 65
    09   thread reclaim                       PASS  threads 5 -> 65 -> 2 after 35s (baseline 5 +2); 20/20 sockets closed by server
    TOTAL rows=11 pass=10 fail=0 xfail=1 skip=0
    RESULT PASS

上面这张表是本轮在 `build/bpb.exe`（sha256 `CB582319A645402D…`，2026-11-02 21:10:17 构建，
端口 18400/18401）上的实测。

修复前的二进制（`tmpscripts/bpb_old.exe`，同样是 25/8 配置）实测：
`07 FAIL 98.79%`、`09 FAIL threads 5 -> 65 -> 62 after 35s`（20 条 socket 一条都没被关），
而 `02/03` 依然全绿 —— 这条回归只在 CPU / 线程维度上暴露。

判定项：

1. `01` 源站自检：直接 HTTP 取那 1 MiB，字节数与 sha256 必须和脚本内生成的期望一致，
   否则后面的失败不能算在 bpb 头上。
2. `02` 顺序 25 次 1 MiB（§2c 的等价验证）：必须 25/25 完整，单次约 20~110 ms、66~69 帧。
   失败特征：卡在 3 KB 上下，脚本报 `stalled: no frame for 8.0s, got 31xx bytes`。
3. `03` 8 条并发各 1 MiB：8/8，内容 sha256 与期望一致。
4. `04a/04b` 半关闭：请求发出后立刻 `shutdown(SHUT_WR)`。会话必须**马上结束**
   （实测 0.00~0.04 s，不占线程）；响应体收不到 —— 客户端 FIN 会拆掉 WS 的下行，xray 行为相同
   （§6e），所以记 `XFAIL`，加 `--strict-halfclose` 才判失败。
5. `05` 未知 WS 路径：`/tr/x`、`/ss/x` 在升级前就 `HTTP/1.1 404`（只编 vless 的二进制，
   见 §0b；路径用 `--bad-paths` 可换）。
6. `06a/06b` 错误 UUID：会话必须被关掉而不是挂着（实测 0.02 s 内收到 close 帧），
   并且**一个负载字节都不许转发**（实测 0 payload bytes）。这一条以前记 `XFAIL`
   —— `parse_vless()` 只在配置的 UUID 带 `-` 时才构造期望值，而面板默认 `config.json`
   的 `vlUUID` 没有短横线，等于任何 UUID 都放行；现在无条件比较，见 §9d。
7. `07` 一个已建立会话空闲 8 s：`(Get-Process -Id <pid>).CPU` 的差值 ≤ 5% 单核
   （实测 0.00%；修复前 97.5%）。Windows 的 CPU 计时 15.6 ms 一跳，1 个 tick 属噪声，
   别拿小数点后几位做判据。
8. `08` 20 个「升级后不发头」的会话：CPU 同样 ≤ 5%（实测 0.19%~1.34%，机器忙时偏高，
   判据仍是 5%），线程数先涨（5 → 65）。
9. `09` 35 s 后（30 s 握手超时 + 5 s 余量）线程回落到基线 +2 以内，且这 20 条 socket 由
   服务端主动关闭（实测 20/20）。

## 9. CLI 自省与凭据加固回归（回归重点）

本轮加了两个命令行能力：`--cur`（正在跑的实例用的是哪个隧道域名）和 `--passwd`（面板凭据
从 `settings.json` 的明文挪进 `<data>/passwd` 的加盐哈希）；另外修了两个安全 / 资源问题：
HTTP poll 循环遇到 `POLLHUP`/`POLLNVAL` 会烧满一核（只做 `connect()+close()` 的端口扫描就能
触发），以及 VLESS 的 UUID 在配置不带短横线时根本不做比较（等于开放代理）。

Windows 构建没有内置隧道、也读不到别的进程的命令行，所以 9a 的“自动发现实例”只在 Linux 上
成立（Windows 只验 `--cur --data` 读文件这条路径）；9b~9d 两边都能验。

### 9a. `bpb --cur`：当前运行实例的隧道域名

Linux（生产机 151.241.88.97：下面两行的 pid / 端口 / 域名 / 状态都取自该机的 `/proc` 与
`panel/tunnel-status` 实测值；`--cur` 本身要新构建的二进制才有）：

    # 1) 一条命令列出所有活着的 bpb 实例
    bpb --cur
    pid      port   tunnel domain                                  state
    7754     8080   examinations-widely-occasion-eating.trycloudflare.com   connected   [panel] data=/root/.bpbdata
    6954     18500  (no tunnel)                                    offline      data=/root/.bpbtest18500

    # 2) 三处来源必须一致（面板 > tunnel-quick.json > config.mainDomain）
    systemctl show -p MainPID --value bpb
    7754
    cat /root/.bpbdata/tunnel-quick.json
    {"hostname":"examinations-widely-occasion-eating.trycloudflare.com", ...}
    python3 -c "import json;print(json.load(open('/root/.bpbdata/config.json'))['mainDomain'])"
    examinations-widely-occasion-eating.trycloudflare.com

    # 3) 重启后域名必然变化：--cur 与 config.json 必须同时更新
    systemctl restart bpb && sleep 10 && bpb --cur
    pid      port   tunnel domain                                  state
    7421     8080   sierra-logo-permit-window.trycloudflare.com   connected   [panel] data=/root/.bpbdata
    python3 -c "import json;print(json.load(open('/root/.bpbdata/config.json'))['mainDomain'])"
    sierra-logo-permit-window.trycloudflare.com

    # 4) 进程没了，实例也必须从列表里消失
    systemctl stop bpb && bpb --cur; echo $?
    no running bpb process found
    1

Windows（无隧道，只验读文件）：

    build\bpb.exe --cur --data tmpscripts\data-passwd-demo --port 18420
    pid      port   tunnel domain                                  state
    0        18420  (no tunnel)                                    offline      data=...\data-passwd-demo

    build\bpb.exe --cur --data tmpscripts\data-nowhere; echo $?
    no bpb instance at ...\data-nowhere (config.json missing)      # 这行在 stderr
    1

    build\bpb.exe --cur
    Windows builds carry no built-in tunnel; pass --cur --data <dir> to read a local instance.

判定项：

1. `pid` 必须是 `systemctl show -p MainPID --value bpb` 的那个 pid（而不是另起一个 bpb 再去问），
   `port` 必须等于该实例的 `--port`，并且和 `ss -lntp` 里它监听的端口一致。
2. 域名以**面板**为准：行尾标 `[panel]` 表示 `/<securePath>/panel/tunnel-status` 回了 200 且带
   `hostname`；面板不可达时退回文件（`[quick tunnel]` / `[mainDomain]`），state 变成
   `unreachable (from files)` —— 不许把文件里的旧域名假装成 connected。
3. quick tunnel 每次启动都重新注册，旧域名在进程退出后就被边缘下线（复用 token 会得到
   “connected 但域名 530”，见 §6b / §6c）。所以**重启后 `--cur` 与 `config.json` 的 `mainDomain`
   必须在同一轮里都变成新域名**，只更新一处就是 bug：客户端会按订阅里的旧域名去连，拿到 530。
   核对方法就是上面第 3 步那两条命令连着跑。
4. `--cur` 只看活进程（扫 `/proc` 的 cmdline）：停掉之后该实例必须消失。
   `docker logs | grep trycloudflare` 会把最后一次的旧域名给你，这正是不拿它当数据源的原因。
5. `--cur --data <dir>` 指向没有 `config.json` 的目录时，stderr 一行 + 退出码 1；
   不许打印一行空记录伪装成健康实例。

### 9b. `bpb --passwd`：面板凭据写在 `<data>/passwd`

四个形态（本机 Windows 实测输出，Linux 上一致）：

    # 0) 还没设过：退出码 1
    bpb --passwd --data ./.bpbdata; echo $?
    no panel credential in ./.bpbdata/passwd
    set one with: bpb --passwd <password>   (user = config.accEmail)
    1

    # 1) 状态形态：只报 user 和盐长度，不打印秘密
    bpb --passwd --data ./.bpbdata
    panel credential: ./.bpbdata/passwd
      user: admin
      hash: sha256, salt 32 hex chars

    # 2) 设置（用户名取 config.accEmail）
    bpb --passwd 'demo-pass-1' --data ./.bpbdata
    password set for user 'admin' in ./.bpbdata/passwd
    cat ./.bpbdata/passwd; stat -c '%a' ./.bpbdata/passwd
    # bpb panel credential -- generated by 'bpb --passwd'
    # user:$sha256$<salt>$<sha256(salt:password)>
    admin$sha256$acfde46f13a6152bb9064acd430fc3fe$ae50bca2714514a0561e47f07345f331b3ce7cd29a808e2fe4c363bf273d358c
    600

    # 3) 指定用户名
    bpb --passwd ops 's3cret' --data ./.bpbdata
    password set for user 'ops' in ./.bpbdata/passwd

    # 4) 本地校验 + 向运行中的面板验证 access
    bpb --passwd 'demo-pass-1' --check --data ./.bpbdata --port 18420
    credential on disk:      match
    live access:             accepted (POST /securepath/login/authenticate -> HTTP 200 + jwtToken)

    bpb --passwd 'nope' --check --data ./.bpbdata --port 18420; echo $?
    credential on disk:      MISMATCH
    live access:             REJECTED (HTTP 401)
    1

判定项：

1. 文件格式固定 `user$sha256$salt$hash`：盐 ≥ 32 hex，`hash = sha256("<salt>:<password>")`；
   POSIX 上落 `chmod 0600`（Windows 没有 chmod，靠目录 ACL）。
2. 状态形态（不带参数）**不得**打印口令或哈希，只允许 user 与盐长度 —— 它要能贴进工单。
3. `--check` 的 accepted 判据是 **HTTP 200 且 `Set-Cookie` 里有 `jwtToken=`**，不是只有 200：
   `POST <securePath>/login` 本身也返回 200（那是登录页 HTML），只看状态码会把“地址或方法写错”
   当成登录成功。本机实测三态：`/securepath/login` 200 无 cookie、
   `/securepath/login/authenticate` 200 有 cookie、错口令 401 无 cookie。
4. 口令错、用户名错都必须 401 → `--check` 打 `REJECTED` 且退出码 1；本地验不过打 `MISMATCH`
   也算失败。用户名大小写不敏感。
5. 登录优先级：`login()` 先查 `<data>/passwd`，**只有**该文件不存在时才回退 `settings.json` 的
   明文口令，并在首次成功登录后把它迁移成 passwd 文件。迁移之后改 `settings.json` 的明文不再
   影响登录；面板的 `update-settings` 改密码会同步重写这个文件，两条路不会打架。

### 9c. 只做 `connect()+close()` 的端口扫描不得烧 CPU

`tmpscripts/scan_cpu.py` 自己起 bpb、量 CPU、做 N 次裸 `connect()+close()`、再量一遍，最后
确认它还在正常应答：

    python tmpscripts\scan_cpu.py --exe build\bpb.exe --port 18410
    scans performed:               200
    0) baseline (readiness probe)        0.00%  threads=4
    1) after 200 connect+close           0.00%  threads=4
    still answering:               HTTP/1.1 302 OK
    RESULT PASS (limit 2.0% of one core)

    # 基线：修复前的二进制（同一条命令，换个端口）
    python tmpscripts\scan_cpu.py --exe tmpscripts\bpb_old.exe --port 18411
    0) baseline (readiness probe)       99.31%  threads=4
    1) after 200 connect+close          99.25%  threads=4
    still answering:               HTTP/1.1 302 OK
    RESULT FAIL (limit 2.0% of one core)

为什么：poll 循环以前只把“可读”当事件，`poll()` 返回 `POLLHUP`/`POLLNVAL` 时既不读也不关，
那个 fd 永远留在集合里、每次 `poll()` 立刻返回 —— 一次“连上就断”的扫描就能让它烧满一核，
而且再也降不下来（旧二进制的 baseline 就已经 ~99%，因为脚本的就绪探测本身也是一次
connect+close）。现在 `POLLHUP|POLLNVAL|POLLERR` 一律按断连处理（关闭并从集合里摘掉），
flush 硬错误时清空待发尾包，避免半关闭连接上无限重试。

判定项：

1. 200 次 connect+close 之后，5 s 窗口的 CPU **< 2% 单核**：实测 `0.00%`；修复前实测 `99.25%`
   （同一个 busy-loop 在别的采样里也出现过 97% 量级，量级一致即可）。
2. 线程数不涨（Windows `(Get-Process -Id <pid>).Threads.Count`，Linux `/proc/<pid>/status`
   的 `Threads:`）：实测扫描前后都是 4。
3. 扫描结束后服务器仍能正常应答：实测 `HTTP/1.1 302 OK`（`GET /` 重定向到 `<securePath>/panel`）。
4. 这条和 §7 的 `07/09` 是同一类空转的两个入口 —— `07` 是“会话建立后空闲”，本条是“连上就断”，
   两个都要压住。

### 9d. 错误 uuid 必须被拒（0 字节 + 关闭）

    # 只跑 01/05/06，并打开 --strict-uuid：能过就判失败
    python tmpscripts\regress_ws.py --port 18400 --pid <bpb pid> \
        --skip 02,03,04,07,08,09 --strict-uuid
    ...
    06a  wrong uuid: no hang                PASS  session ended after 0.00s (close frame)
    06b  wrong uuid: no data                PASS  0 payload bytes (close frame)

整轮就是 `pwsh -File tmpscripts\run_regress_ws.ps1 -StrictUuid`（`TOTAL rows=11 pass=10
fail=0 xfail=1 skip=0`；剩下那个 `XFAIL` 是 `04b` 半关闭的响应体，与凭据无关）。

判定项：

1. 升级成功后发一帧带**错误** uuid 的 VLESS 头 + 一个 GET：会话必须马上以 close 帧结束
   （`06a`，实测 0.00~0.02 s），不许挂着占线程。
2. 不得转发任何负载字节（`06b` 必须 0 字节），源站侧也不许出现这次 GET。
3. 修复前 `parse_vless()` 只在配置 uuid 带 `-` 时才构造期望值，而面板生成的 `vlUUID` 没有
   短横线，于是比较被整段跳过、任何 uuid 都能过 —— 那就是个开放代理。现在不看去不去短横线
   都比 32 个 hex，配置里的 uuid 本身不合法时 fail closed（直接拒）。
4. `--strict-uuid` 原先只是把“能过就判失败”的老行为从 `XFAIL` 抬成硬判据；修好之后 `06b`
   无条件 PASS，加不加这个开关结果一样（本轮两种跑法都验过）。

## 10. 隧道数据面流控与吞吐回归（回归重点）

隧道（`src/tunnel/`）的数据面有两类退化，都不会报错、只会变慢，所以必须靠数字卡：

- **二次方拷贝**：`client.cpp` 的抽水循环如果只在循环外判断高水位，`toEdge` 会涨到 MB 级，
  之后每次前移都 memmove 整个尾巴。表现：吞吐跌到 16~21 MB/s，每 GB 烧 30 秒 CPU，
  `perf record` 里 **libc 的 memcpy 循环占 70% 以上**。
- **连接级窗口被卡在 65 KB**：只靠每个 DATA 帧还 1 次信用时，连接窗口永远只有一个帧，
  吞吐 ≈ 64 KB/RTT，与 CPU 空闲无关。

### 10a. 全链路吞吐 / CPU 基线（同机客户端）

被测机：1 核 / 469 MB。客户端用 xray 跑在同一台机上（所以客户端也吃这颗核），
源站用 `python3 -m http.server 18000` 提供 `/root/big100m.bin`。

    # 1) 先量裸链路，确认不是链路本身只有这个速度
    curl -s -o /dev/null -w '%{speed_download}\n' 'https://speed.cloudflare.com/__down?bytes=50000000'
    # 期望：本机实测 48.6~48.8 MB/s，cachefly 100 MB 为 53.7 MB/s

    # 2) 全链路单流 + 4 并发（客户端配置见 tmpscripts/chain*.json 的生成脚本）
    #    单流 100 MB ×2 轮、4×100 MB ×1 轮，CPU 取 /proc/<bpb pid>/stat 的 utime+stime 差值

判据（本机 1 核，链路 48.8 MB/s）：

| 项 | 门槛 | 修复前 | 修复后实测 |
|---|---:|---:|---:|
| 单流吞吐 | ≥ 35 MB/s | 16~21 | **40~47** |
| 4 并发聚合 | ≥ 25 MB/s | — | **31.8** |
| 每 GB CPU | ≤ 7 s | 32.9~35.7 | **5.2~5.8** |
| 单流 CPU 占比 | ≤ 40% 一核 | 65~95% | **24%** |

### 10b. 定位手法（不装 profiler 也能查）

    perf record -F 499 -g -o /tmp/perf.data -p <bpb pid> -- sleep 4
    perf report -i /tmp/perf.data --stdio --sort dso,symbol | head -20
    # 症状：libc.so 里一串 0x1640xx 的 vmovdqu64 循环 → memcpy/memmove 热点

    perf stat -p <bpb pid> -e syscalls:sys_enter_sendto,syscalls:sys_enter_recvfrom -- sleep 3
    # 每次系统调用搬运的字节 = 传输量 / 调用数；低于 8 KB 说明在搬碎块

### 10c. 流控本身要看的两点

1. 建连后必须发一次 `WINDOW_UPDATE(0, 4 MB)`（连接级窗口只能靠它放大）；
2. 还信用必须按 ~1 MB 批量，**不能**每个 DATA 帧还一次 —— 后者既卡住窗口，又让每帧多两次
   控制帧写入（批处理也因此失效）。

回归时可开 `--log trace` 数 `[h2 tx] WINDOW_UPDATE` 的行数：
100 MB 传输应只有 ~100 条（每 MB 一条），出现 6400 条说明退回了逐帧还信用。


## 11. 面板认证与派生配置回归（回归重点）

三件事在这一轮同时改了，任何一件回退都会静默把面板变回“免密”或把隧道回源指错：

1. **回环地址不再是免密通行证**。以前 `from_loopback(req)` 一真就直接 return true，
   本机浏览器不用登录、`ssh -L` 转发过来的请求也不用登录（服务端看到的同样是 127.0.0.1），
   连**经自己隧道进来的公网请求**也不用登录（隧道回源也发到 127.0.0.1）。
   现在浏览器必须登录，命令行靠 `X-BPB-CLI` 头拿到全权限。
2. **浏览器会话 10 分钟、且是会话 cookie**（`Max-Age`/`Expires` 都不带）。
3. **隧道回源地址由进程自己算**，不再接受表单里填的值。

### 11a. 回环地址不再等于管理员

    D=./.bpbtest11; rm -rf $D
    ./build/bpb --host 127.0.0.1 --port 18430 --data $D &   # 先不设密码
    curl -s -o /dev/null -w 'no-pw settings=%{http_code}\n' http://127.0.0.1:18430/securepath/panel/settings
    # 期望 200：还没设密码，面板本来就该能开

    ./build/bpb --passwd admin s3cret --data $D
    curl -s -o /dev/null -w 'loopback settings=%{http_code}\n' http://127.0.0.1:18430/securepath/panel/settings
    curl -s -o /dev/null -w 'loopback warp=%{http_code}\n'     http://127.0.0.1:18430/securepath/panel/warp-status
    # 期望两行都是 401：**这是本节的核心判据**，修复前这里会是 200

判定项：

1. 设了密码之后，**任何**不带凭据的面板请求都 401，包括从回环地址来的；
   `/<securePath>/panel` 本身 302 到 `login`，而 `panel/*` 一律 401。
2. `GET <securePath>/login` 仍要能打开（那是登录页），否则会锁死。

### 11b. 会话 cookie：10 分钟、浏览器关掉就没

    curl -s -D - -o /dev/null -X POST http://127.0.0.1:18430/securepath/login/authenticate \
      -H 'Content-Type: application/json' --data '{"username":"admin","password":"s3cret"}'
    # 期望 Set-Cookie: jwtToken=...; Path=/; HttpOnly; SameSite=Strict
    #      不得出现 Max-Age 或 Expires
    # 期望 JWT 载荷里 exp - iat == 600

    curl -s -o /dev/null -w '%{http_code}\n' -H "Cookie: jwtToken=<token>" \
      http://127.0.0.1:18430/securepath/panel/settings
    # 期望 200；同一 token 在 10 分钟后必须 401

判定项：

1. `Set-Cookie` **不带** `Max-Age`/`Expires`，这样浏览器关闭即丢弃（会话 cookie）。
2. JWT 的 `exp = iat + 600`；只靠 cookie 的“会话”属性不够，页签开着 10 分钟也必须失效。
3. 面板里任何 `panel/*` 请求拿到 401 都整体跳登录页（`redirectToLogin()`），
   不要逐个调用点自己弹 toast。

### 11c. 命令行全权限、免密、免令牌

    # 设了密码之后，命令行依然直接读写，不需要任何凭据
    curl -s -o /dev/null -w 'cli=%{http_code}\n' -H 'X-BPB-CLI: 1' \
      http://127.0.0.1:18430/securepath/panel/settings        # 期望 200

    # 没有这个头就是从浏览器/隧道来的，必须登录
    curl -s -o /dev/null -w 'plain=%{http_code}\n' \
      http://127.0.0.1:18430/securepath/panel/settings        # 期望 401

    # --cur 也是靠这个头拿实时状态，不需要登录、也不需要令牌文件
    ./build/bpb --cur --data $D --port 18430
    # 期望 state 列是 offline/connected（[panel]），而不是 locked/unreachable

判定项：

1. **没有任何令牌文件**：`<data>/` 下不得出现 `clitoken`；命令行不该有需要运维维护的秘密。
   判定：`ls $D | grep -c clitoken` 必须是 0。
2. `X-BPB-CLI` 只对**回环地址**的请求有效。从外部地址带这个头必须无效
   （`curl --interface <lan-ip>` 或从另一台机器测），否则等于把面板对公网开放。
3. 这个头是**浏览器发不出来**的东西：顶层导航不能带自定义请求头，跨源 JS 加头会触发 CORS 预检，
   而服务端从不回应预检。所以「带上这个头」等价于「在本机以操作者身份跑程序」。
4. 设过密码之后，`--cur` 仍然要显示实时状态（`[panel]`），不能退化成 `locked (login required)`。
5. 隧道场景要单独确认：常驻隧道时，经隧道进来的面板请求**必须**要求登录
   （回源连接同样来自 127.0.0.1，这一条正是老实现漏掉的口子）。

### 11d. WireGuard 开关不能在没有账号时打开

    curl -s -X PUT -H 'Content-Type: application/json' -H "Cookie: jwtToken=<token>" \
      --data-binary '{"wgOutboundEnabled":"true"}' \
      http://127.0.0.1:18430/securepath/panel/update-settings
    # 期望 success:false，message 提示先注册 WARP 账号

    curl -s -H "Cookie: jwtToken=<token>" http://127.0.0.1:18430/securepath/panel/warp-status
    # 期望 enabled:false, accounts:0

判定项：

1. 账号池为空时保存**必须拒绝**，并把 `wgOutbound.enabled` 保持 `false`
   —— 不能“存了 but 没生效”，那正是 `warp=off` 却显示「已启用」的来源。
2. 拒绝时 `body` 是 `null` 而原因在 `message`：面板必须按“非数组”分支提示，
   否则 `body.forEach` 会抛 TypeError，操作者只看到一条无意义的报错。
3. `start_wg_outbound()` 报错要能读：账号池空、握手超时是两种不同的原因。

### 11e. 隧道回源地址不接受表单值

    curl -s -X PUT -H 'Content-Type: application/json' -H "Cookie: jwtToken=<token>" \
      --data-binary '{"cfTunnelOrigin":"10.0.0.9:1234"}' \
      http://127.0.0.1:18430/securepath/panel/update-settings -o /dev/null

    curl -s -H "Cookie: jwtToken=<token>" http://127.0.0.1:18430/securepath/panel/settings \
      | python3 -c "import json,sys;print(json.load(sys.stdin)['body']['proxySettings']['cfTunnelOrigin'])"
    # 期望 127.0.0.1:18430（= 实际 --port），而不是 10.0.0.9:1234

判定项：

1. `originHost`/`originPort` 一律由 `store_.listen_port()` 重算，请求里带什么都被忽略。
2. 面板上 `#cfTunnelOrigin` 是 `readonly`；「监听端口」改名为「对外端口」，
   并说明无端口映射时它等于实际监听端口。
3. 两者语义不能重叠：对外端口是**订阅里写的**端口，回源是**隧道转给谁**，
   混用会让隧道转到没人监听的端口（边缘 502/530）。

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

## 7b. 多架构二进制

CI 会为 amd64 / arm64 / armv7 / 386 / riscv64 各产出一个静态二进制。本地验证某一架构可执行：

    docker run --rm -v "$PWD:/w" -w /w --platform linux/arm/v7 alpine:3.22 ./bpb-linux-armv7 --help

（需要宿主机装好 qemu-user 的 binfmt，或在 CI 里跑。）

## 0b. 入栈协议按编译期裁剪（回归重点）

协议清单是**编译期**决定的，没编进去的协议不能被编译、不能被分发、不能出现在面板和订阅里。

1. **只编一个协议**：
   `cmake -S . -B /tmp/one -DBPB_INBOUNDS=trojan` → 配置期必须打印
   `-- bpb inbounds: trojan`；`/tmp/one/bpb --log info` 的启动行必须以
   `inbounds: trojan` 结尾（多一个协议都不对）。

   **例外是 vless**：XHTTP 是“传输绑定”而不是独立协议，CMake 把它和 VLESS 一起编，
   所以 `-DBPB_INBOUNDS=vless` 的启动行是 `inbounds: vless,vless-xhttp`。
   同理 `-DBPB_INBOUNDS=vless-xhttp` 单独选也要能链接（早期版本会 `undefined reference`）。
   **正确做法是以 CMake 写出的 `expected-inbounds.txt` 为准**，不要自己推这条规则：
   配置期会把运行时列表写进该文件，CI 的校验步骤直接读它比对启动行。
2. **未选中的协议不参与编译**：构建日志里不应出现
   `trojan_ws.cpp` / `shadowsocks_ws.cpp` 这两个翻译单元。
3. **全协议**：`-DBPB_INBOUNDS=all` → `inbounds: vless,trojan,shadowsocks,vmess,vless-xhttp,vless-grpc`。
   WebSocket 协议排在前四个，两个新传输（XHTTP、gRPC）排在后面；它们不走 WebSocket 升级，
   分别由 HTTP 服务端的 takeover / pre-takeover 钩子接管（见第 11 节）。
4. **非法协议名**：`-DBPB_INBOUNDS=nope` 必须配置期直接 FATAL_ERROR 并列出可用协议。
5. **路径分发**：编入 vless 的二进制访问 `/tr`、`/ss` 都是 404；
   编入 all 时 `/vl` `/tr` `/ss` 都能升级成 WebSocket，`/vlx`（XHTTP）与
   `/vlg/Tun`（gRPC）分别被对应传输接管。默认 `BPB_INBOUNDS=vless` 含 XHTTP 但**不含 gRPC**，
   发布构建要用 `all` 或显式 `vless,vless-grpc`。
6. **面板裁剪**：`GET /<sp>/panel/settings` 的 `body.inbounds` 与实际编入一致；
   `PUT /<sp>/panel/update-settings` 提交 `{"protocols":"<没编进去的协议>"}` 返回 400，
   提交混合列表时没编进去的项被静默剔除。
7. **订阅裁剪**：`sub::get_protocols()` 与协议表求交集；把一个没编进去的协议写进
   settings.json，生成出来的订阅里不应出现它。

## 11. 传输开关与订阅一致性（回归重点）

面板「通用」区两个开关 `enableXHTTP` / `enableGRPC` 同时决定两件事：订阅里是否多出
该传输的线路，以及服务端是否还接受该入口。两者必须同步，否则会出现「订阅里删掉了、端口还开着」的隐藏入口。

本地自检（会自己起一个临时实例，不碰正式数据目录）：

    cmake -S . -B build-all -G Ninja -DCMAKE_BUILD_TYPE=Release -DBPB_INBOUNDS=all
    cmake --build build-all
    python tmpscripts/transport_selftest.py   # 31 项，订阅侧
    python tmpscripts/gate_selftest.py        # 4 项，服务端拦截

预期：两个脚本都以 `ALL PASS` 结束。覆盖点：

1. **默认两个都关**：`panel/settings` 的 `proxySettings` 里 `enableXHTTP=false`、
   `enableGRPC=false`，且不再有旧的 `transport` 键；raw 订阅只有 `type=ws`。
2. **打开后是追加不是替换**：WebSocket 线路一条不少，XHTTP / gRPC 各补一份，备注后缀 ` XHTTP` / ` gRPC`；
   主机数为 N 时三种传输的条数必须相等（Best Ping 的负载均衡条目只算一条，不随传输数翻倍）。
3. **内容正确**：xray 配置 `network=xhttp` + `xhttpSettings.path=/vlx`；
   `network=grpc` + `grpcSettings.serviceName=vlg`；share link 里 grpc 的 `alpn` 必须是 `h2`。
4. **客户端能力取舍**：Clash / sing-box 订阅里有 gRPC、**没有** XHTTP（这两个内核不支持 XHTTP）。
5. **关掉即回收**：再写回 `false` 后，订阅里两种传输的条目全部消失，条数回到开关前的基线。
6. **服务端也关**（`gate_selftest.py`）：开关关闭时发 h2 前言收到的是 HTTP/1.1 应答（说明 h2 接管没有发生），
   `GET /<sp>/vlx/<sid>` 落回面板；打开后前者回 SETTINGS 帧、后者回 `text/event-stream`。
7. **没编进就不生成**：只编 vless 的二进制（`BPB_INBOUNDS=vless`，其内部已含 vless-xhttp 但不含 vless-grpc）
   把 `enableGRPC` 打开，订阅里也不应出现 gRPC 线路 —— 生成侧按 `inbound::has()` 过滤。

真机互通（VPS，1 核 / 469 MB，官方 xray 26.3.27 客户端）实测，供对照：

| 传输 | 结果 | 吞吐 | 每 GiB CPU |
|---|---|---|---|
| XHTTP | 25/25 × 1 MiB 逐字节一致 | 下行 84.7 MiB/s，上行 15.1 MiB/s | 3.8–5.0（下）/ 2.9–3.8（上）cpu·s |
| gRPC | 25/25 × 1 MiB 在 0.96 s 内完成 | 137.2 MiB/s | 1.33 cpu·s |

空载与并发：XHTTP 200 并发会话峰值 RSS 110 MB（约 550 KB/会话，每会话 3 条 128 KB 栈线程），
客户端停止后 30 s 回到 14 MB、125 s 回到 6.5 MB；gRPC 200 条流跑在 1 条 TCP 上 RSS 10.3 MB。
两者空载 CPU 都是 0.0–0.1%，没有空转。
## 12. 两个传输开关对内存与并发的影响（回归重点）

问题：打开 `enableXHTTP` / `enableGRPC` 会不会拉高内存、多占线程？结论分两层。

**第一层：只打开开关、不走该传输时，开销为零。** 同一二进制、同一数据目录，只改 settings.json 的两个布尔值后重启：

| 状态 | idle RSS | 线程 |
|---|---|---|
| 两个都关 | 5816 kB | 5 |
| 只开 XHTTP | 5884 kB | 8 |
| 只开 gRPC | 5692 kB | 5 |

差值在 ±70 kB / ±3 线程以内，属于进程噪声：开关只决定 HTTP 服务端的两个钩子是否接管连接，不预分配任何缓冲。
本地 Windows 版同样结论（10.3 MB / 10.1 MB / 10.1 MB，线程都是 4）。

**第二层：真正跑该传输时，XHTTP 的成本明显高于 gRPC。** 30 并发下载，每个传输用各自真实的 xray 客户端，
每轮都是全新进程（上一轮残留会污染下一轮的基线，务必重启）：

| 传输 | 连接数 | idle RSS | 峰值 RSS | 每会话 | 峰值线程 | 客户端停止后 |
|---|---|---|---|---|---|---|
| WebSocket（基线） | 30 | 5816 kB | 8280 kB | **82 kB** | 92 | 60 s 内回到 9.9 MB / 2 线程 |
| XHTTP | 60 | 5884 kB | 36428 kB | **1018 kB** | 153 | 20 s 回到 8.5 MB / 3 线程 |
| gRPC | 1 | 5692 kB | 5792 kB | **3 kB** | 93 | 60 s 内回到 7.2 MB / 3 线程 |

读法：

1. **XHTTP 每会话约 1 MB**，是 WebSocket 的 12 倍。原因是它每个会话要同时持有下行 GET 流、按 seq 重排的
   乱序缓存（上限 256 块 / 4 MB）、上行队列（4 MB 上限）和至少 2~3 条 128 KB 栈的线程。
   30 并发时线程 153、连接 60（一会话一对 GET+POST 连接）。
2. **gRPC 几乎是免费的**：一条 TCP 承载全部 stream，RSS 峰值只比空载高 100 kB，
   因为每个会话只是同一连接上的一个 stream，没有独立连接和独立队列。
3. **都没有泄漏**：客户端停掉后连接立刻归零，XHTTP 20 s 内、gRPC 60 s 内内存回到接近空载；
   继续观察到 t+240 s 稳定在 8.5 MB，不再增长。
4. **空载不空转**：三种状态 17 s 采样期 CPU 0.02–0.56 s，主要是测量本身的开销。

复现：

    # 服务器与客户端配置里的 UUID 必须一致（新数据目录会随机生成 UUID）
    python3 tmpscripts/m_transport3.py 30
    # 每轮重启进程、探测一次 200 后再加压，探测失败就跳过而不是记 0

**踩过的坑**：三轮共用同一个长期进程，第二轮会把第一轮没还回去的内存当成自己的基线
（曾测出 gRPC “空载 56 MB”）；不校验探测结果就加压，得到的是 30 个连不上服务端的空转客户端
（conn=0、cpu=0）。这两条都会让结论完全反向，所以脚本里现在强制重启 + 强制 probe。
## 0c. 每协议一个独立二进制（发布前自查）

用官方 Xray 客户端（outbound 分别配 vless / trojan / shadowsocks / vmess，
streamSettings.network=ws、security=none、路径对 /vl /tr /ss /<uuid>-vm）各跑一次：

    curl -x socks5h://127.0.0.1:<port> -o NUL -w '%{http_code} %{size_download}\n' https://example.com/

预期四个都是 200；服务端 --log debug 能看到对应的 [trojan] host:port / [ss] host:port /
[vmess] host:port。Shadowsocks 用 method=aes-256-gcm、密码填面板 UUID；VMess 用
alterId 0 + security auto。sing-box 客户端同样要过（alter_id 0，transport ws，
可选 max_early_data 2048 + early_data_header_name）。

**矩阵自查（本地可完整复现 CI 的断言）**：对每个协议各做一次 -DBPB_INBOUNDS=<proto> 的独立构建，
配置期打印的列表必须与 build/expected-inbounds.txt 一致，二进制必须 static，启动行必须等于该文件。
注意 vless 的期望值是 inbounds: vless,vless-xhttp（XHTTP 跟着 VLESS 一起编），其余协议是单个名字。
脚本：tmpscripts/matrix.sh，期望末行 MATRIX-RESULT fail=0。

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
