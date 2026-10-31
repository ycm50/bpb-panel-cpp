# 测试清单

改动 C++ 源码后按顺序执行。全部可脚本化，不需要 Node.js。

## 1. 编译

    cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
    cmake --build build

预期：生成 build/bpb，全程不使用 MSVC。

另外验证"单文件可运行"：把 build/bpb（或 bpb.exe）单独拷到空目录直接运行，应当自动创建 data/
并能在 http://127.0.0.1:8080/securepath/panel 打开面板（面板资源已内嵌，不需要 --assets）。

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

    ./build/bpb --port 8443 --data ./data --tls-cert cert.pem --tls-key key.pem

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

### 5b. 外部 warp-rust 进程（无需 NET_ADMIN）

WARP 出栈由子模块 `third_party/cf-warp-rust` 编译出的独立进程承担，
bpb 只负责渲染配置、监督进程、通过它的 SOCKS5 拨号。相关代码：
`src/net/warp_proc.cpp`（监督）、`src/proxy/session.cpp`（拨号）。

**核心约束：注册只发生一次。** 凭据放在 `data/warp/account.json`，
只要该文件存在就不会重新注册。做任何测试前先确认它存在，
**不要删除它**，也不要在短时间内反复启动「没有凭据」的实例。

1. **子模块与编译**

       git submodule update --init --recursive
       cd third_party/cf-warp-rust && cargo build --release --locked && cd -

   预期：`target/release/warp-rust` 生成，`warp-rust --version` 输出 0.4.x。
   注意 `Cargo.toml` 声明了 `rust-version = "1.91"`：本机 rustc 低于 1.91 时
   cargo 只打一行 "requires rustc 1.91 or newer" 然后以 **101** 退出，看起来
   就像玄学失败（CI 早期就是这么踩的坑）。
   **CI 现在不编译 warp-rust**：打包时直接从上游 release 取
   `x86_64/aarch64-unknown-linux-musl` 两个静态包（先校验上游 sha256），
   见 `.github/workflows/build.yml` 的 release 任务。本地需要时再按上面手动编。

2. **进程监督与就绪**（把二进制放到 bpb 同目录，或设置 `wgOutbound.binary`）

       ./bpb --data ./data --port 21119

   预期日志：

       warp outbound enabled: ready (pid 12345, socks 127.0.0.1:11080)
       bpb native listening on http://0.0.0.0:21119 (secure path: /securepath/)

   再确认：`ss -lntp | grep 11080` 由 `warp-rust` 持有；
`data/warp-rust.toml` 已生成；`data/warp-rust.log` 里出现
`WireGuard tunnel established!`。

3. **SOCKS5 出站**

       curl -s --max-time 20 --socks5-hostname 127.0.0.1:11080 https://api.ipify.org

   预期：返回 Cloudflare 的出口地址；同时访问 cdn-cgi/trace 应看到 `warp=on`。

4. **端到端：VLESS -> bpb -> WARP**

   用 xray 以 VLESS over WS 连本机 bpb，再从它的 socks 出去（security 用 none，
   ws path 用 /<securePath>/vl）。预期出口是 WARP 地址而不是本机 IP，
   说明面板流量确实走了 WARP。

5. **注册幂等性**（重要，防止重复注册）

       md5sum data/warp/account.json
       # 停掉 bpb、重启三次，再比对
       md5sum data/warp/account.json

   预期：三次之后 md5 不变，`data/warp-rust.log` 里没有新的
`Registering new device`。若出现，说明数据目录指向了临时路径。

6. **进程崩溃后自动重启**

       kill -9 $(pgrep -f "warp-rust --config")

   预期：bpb 不退出，2 秒内重新拉起子进程并重新就绪；日志里没有重新注册。
   连续崩溃超过 5 次（10 分钟窗口）后 bpb 停止重启并报 `warp-rust keeps exiting`，
   避免无限重启风暴。

7. **静态内存与自动并发上限**（无连接时测）

       for p in $(pgrep -x bpb) $(pgrep -x warp-rust); do
         echo "$p $(awk '/^Rss:/{print $2}' /proc/$p/smaps_rollup) KB rss,
               $(awk '/^Anonymous:/{print $2}' /proc/$p/smaps_rollup) KB anon"
       done

   预期（静态、零连接）：合计 RSS 约 7.5 MB、匿名约 1.4 MB、共 4 个线程。
   RSS 里大头是静态二进制的文本映射，可回收，不要拿它当真实成本。

   再确认自动并发按容器上限推算：

       grep -E '^(tcp_buffer_size|max_concurrent_connections)' data/warp-rust.toml

   预期：64 MiB → `16 / 65536`；512 MiB → `122 / 262144`。
   若在嵌套 cgroup 里测，程序应读到自己所属的那层，而不是挂载根。

   > 小内存机器的真实瓶颈常常是 **pids** 而不是内存：实测 `pids.max=128` 时
   > 122 条并发连 `fork` 都失败。压测前先看 `pids.max`。
## 6. 资源占用

    docker stats --no-stream bpb

预期：镜像约 7.5 MB，空载内存 1.5 ~ 2 MB，压测峰值约 4 MB。

## 6b. 隧道重连

隧道断开后必须自动重连并重新注册，不能等到进程重启：

1. 启动带隧道的实例，确认日志出现 `REGISTERED with edge`；
2. 掐断到边缘的 TCP：`ss -K dst <edge-ip> dport = 7844`；
3. 1~30 秒内依次出现 `edge connection lost`、`reconnecting in Ns`、
   `connected to edge`、`REGISTERED with edge`；
4. 重连后面板与 `/vl` 仍返回 200。

同时确认空闲与长连接下 CPU 不空转：`/proc/<pid>/stat` 的 utime+stime 在 6 秒内应为个位数。

## 7. 多架构二进制

CI 会为 amd64 / arm64 / armv7 / 386 / riscv64 各产出一个静态二进制。本地验证某一架构可执行：

    docker run --rm -v "$PWD:/w" -w /w --platform linux/arm/v7 alpine:3.22 ./bpb-linux-armv7 --help

（需要宿主机装好 qemu-user 的 binfmt，或在 CI 里跑。）