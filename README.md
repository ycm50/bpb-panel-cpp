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
- [安装脚本踩过的坑](#安装脚本踩过的坑都已修)
- [从源码构建](#从源码构建)
- [命令行](#命令行)
- [命令行与浏览器的权限怎么分开](#命令行与浏览器的权限怎么分开)
- [重启：bpb --res pid](#重启bpb---res-pid)
- [状态以磁盘为准，且只在按钮上刷新](#状态以磁盘为准且只在按钮上刷新)
- [入栈协议与按协议构建](#入栈协议与按协议构建)
- [日志开关](#日志开关)
- [接口](#接口)
- [客户端怎么连](#客户端怎么连)
- [Cloudflare Tunnel](#cloudflare-tunnel)
- [隧道回源由进程自己决定，不能手填](#隧道回源由进程自己决定不能手填)
- [数据面：WebSocket 入栈](#数据面websocket-入栈)
- [WARP 出口](#warp-出口)
- [性能实测](#性能实测)
- [架构](#架构)
- [测试](#测试)
- [CI 与发布](#ci-与发布github-actions)
- [Windows 构建的两个坑](#windows-构建的两个坑)
- [许可证](#许可证)

## 单一分支

只有一个分支 `warp-built-in`。WARP 出栈在**进程内**用 `src/wg` + lwIP 实现，
单二进制、零外部依赖、不需要 `NET_ADMIN`；曾经并行维护的「外部 `warp-rust` 进程 +
本地 SOCKS5 转发」方案已移除，它的面板、订阅、隧道、CLI 与密码功能早已与内置实现完全一致，
再维护两套 WARP 数据面只会让两边同时漂移。

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
- **WARP 出口**：**内置用户态 WireGuard**，见 [WARP 出口](#warp-出口) ——
  Noise IK + lwIP 全在进程内，无需特权、无需外部程序
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
| `--protocol NAME` | 该二进制编入的入栈协议，默认 `vless`（release 里是 `bpb-linux-<arch>-<协议>`）。要用 gRPC / XHTTP 必须显式 `--protocol all` |
| `--passwd PW` | 装完给面板设这个密码；**不传就随机生成一个并只打印一次** |
| `--mem-max N` | 内存上限（MiB）。同时写进 unit 的 `MemoryMax` 和进程的 `--mem-max`，默认取 `bpb --mem-default`（当前 64）。改了它会同时改 cgroup 上限和中继缓冲池预算 |
| `--no-tunnel` | 不开隧道，只在本机端口提供面板 |
| `--uninstall` | 停服务并删除，数据目录保留 |

装完会打印这几项：

    面板（本机）: http://127.0.0.1:8080/securepath/panel
    面板（公网）: https://<随机>.trycloudflare.com/securepath/panel
    隧道域名    : <随机>.trycloudflare.com
    面板密码    : <随机生成的密码>   # 只在这次输出里出现

**密码是强制项**。临时隧道会把面板挂到公网上，域名就是唯一的"秘密"；
不留密码等于谁拿到域名谁就能进面板改设置、读订阅、取 WARP 账号。
所以脚本在建服务之前先写 `<data>/passwd`（加盐 SHA-256，0600）：
`--passwd` 给了就用它，没给就生成 24 位十六进制密码并打印一次。
已经设过密码的实例重跑脚本**不会覆盖**（否则等于把密码换成操作者没看见的随机串）。

注意两点：

- **`--port` 必须同时决定隧道回源端口**。`cfTunnel.originPort` 在二进制里写死默认 8080，
  面板跑在别的端口时若不同步这个值，隧道会注册成功但转发到一个没人听的端口。
  脚本已经处理了这一点（新建和已有 `settings.json` 都会改）。
- **`--data` 不是默认值时是独立实例**：服务名变成 `bpb-<目录 slug>`、二进制装到
  `/usr/local/lib/`，不会覆盖 `bpb.service`。用它在同一台机器上测试不会踢掉正式面板。
  对应地用 `sh install.sh --uninstall --data <那个目录>` 卸载。
  路径会先规范化（`//`、尾斜杠、`./`、`../`），所以 `/root/.bpbdata/` 仍然算默认实例。

临时隧道的域名不保证长期有效。要固定域名就填命名隧道 token：
`/<sp>/panel` → Cloudflare 隧道 → 隧道 Token。

### 安装脚本踩过的坑（都已修）

这一节记录的是**实测**出来的问题，不是推测；每个都有复现路径，改完又用同一个路径验过。

**1. 设过密码的实例，装完报不出隧道域名。**
脚本结尾用 `curl http://127.0.0.1:$PORT/$SP/panel/tunnel-status` 取域名。这个接口要凭据，
于是任何**已经设过密码**的实例（也就是每一次重装、每一次升级）都返回 `401`，域名解析成空，
脚本打一行 `tunnel domain not assigned yet; check journalctl` —— 而隧道其实连得好好的。
现在这里带 `X-BPB-CLI: 1`，命令行本来就该有全权限。

**2. `--no-tunnel` 对已有安装无效。**
旧代码只在 python3 存在时才写 `cfTunnel.enabled=false`，没有 python3 就只打印一句
"自己改 originPort"，隧道照旧开着。现在**有 python3 就整块 JSON 读改写**
（端口写成整数、开关两个方向都写、缺 `cfTunnel` 就补出来）；
**没有 python3 就只做 sed 改端口，然后回读校验**：端口不是裸整数就恢复备份并报错，
绝不留一个会让进程启动即崩的文件。

**3. 反过来也一样：重跑脚本不会把隧道重新打开。**
只写了关闭方向，于是 `--no-tunnel` 跑过一次之后，再跑一次默认的安装脚本，
`enabled` 还是 `false`，进程根本不连隧道，域名永远打印不出来。现在两个方向都写。

**4. 把 `--local` 指向 Windows 二进制会装上去再失败。**
两个平台产物同名，装完 systemd 只会反复重启，报错也看不出原因。现在读文件头，
是 `MZ` 就直接拒绝并说明这是 Linux-only 安装脚本。

**5. 没有 curl 时会空转 40 秒再怪面板。**
下载那一步 curl/wget 都接受，但就绪探测用的是 `curl -w %{redirect_url}`，wget 做不了。
现在缺少 curl 时提前报错，而不是等 40 秒后说"面板没应答"。

**6. `--uninstall` 不带 `--data` 时会误删默认部署。**
`--data` 决定服务名和安装前缀，卸载时不重复它，脚本就按 `bpb` 去删——
在默认安装上这正是**真实部署**，删完还打印 "uninstalled"。现在删不到东西会明确报
`nothing installed as 'bpb'` 并提示补 `--data`，退出码 1，不再假装成功。
（写这一节的过程里，这条命令在测试机上真的把部署删掉过一次，从备份恢复的。）

**7. `--uninstall` 会漏掉 drop-in。**
`/etc/systemd/system/bpb.service.d/`（例如手写的 `TasksMax` 覆盖）不停用也不删，
重装同名服务时它会继续生效。现在随 unit 一起删。顺手也 `pkill` 掉 nohup 装的残留进程，
否则删了二进制它还在占端口，下次装就 "listen failed"。

**8. 面板默认没有密码，而隧道默认是开的。**
新装写的 `settings.json` 里 `"pwd":""`、`<data>/passwd` 也不存在，
于是 `Store::has_pwd()` 为假、所有路由都不要求登录；`securePath` 又是固定的
`securepath`。临时隧道把面板挂到公网后，**谁拿到域名谁就是管理员**。
现在脚本在建服务**之前**写凭据：`--passwd` 给了用它，没给就生成 24 位十六进制串
并在结尾打印一次（只是打印，不落在任何文件里——文件里只有加盐 SHA-256）。
已存在凭据的实例重跑不会覆盖。

**9. `--port 08080` 会写出一份非法 JSON，服务无限重启。**
端口校验只过滤字符，`08080` 能过；它被原样写进 `originPort`，而 JSON 不允许前导零，
nlohmann 整份拒绝、`load()` 失败、进程退出、`Restart=always` 再拉起……
脚本最后报"面板没应答"。现在端口在写文件**之前**用 `sed 's/^0*//'` 去掉前导零
（注意不能用 `$((PORT))`：dash 会把前导零当前八进制，`08080` 直接
`Illegal number` 崩掉）。

**10. 手改过的 `settings.json` 会让进程启动即崩。**
`"originPort": "8080"`（字符串）是合法 JSON，但二进制用
`json.value<int>()` 读它，抛 `type_error.302`，而 `start_from_store()` 外面没有
try/catch，于是 `std::terminate`。旧脚本的 sed 只匹配裸数字，静默不改。
现在有 python3 时按类型重写（字符串/浮点都变成整数），
没有 python3 时改完回读校验，不对就恢复备份并报错。

**11. 没有 systemd 时的 `pkill` 永远匹配不到。**
真实 argv 是 `bpb --host 0.0.0.0 --port N --data DIR`，旧模式
`"$PREFIX/bpb --port N"` 要求 `--port` 紧跟二进制路径，因此从不匹配：
旧进程继续占端口，新进程 `listen failed` 退出，而就绪探测问的是**旧进程**，
脚本于是报告升级成功——实际跑的还是旧二进制。现在模式是
`"$PREFIX/bpb .*--port N( |$)"`。

**12. `--data /root/.bpbdata/` 会装成第二个实例。**
"是不是默认实例"是纯字符串比较，多一个尾斜杠就不相等，于是服务名变成
`bpb-root-.bpbdata`、二进制装到 `/usr/local/lib/`，正式 `bpb.service` 仍跑旧版；
再 `--uninstall --data /root/.bpbdata` 又找不到它。现在路径先规范化。

**13. `--local` 指向别的架构会装上去再 `Exec format error`。**
只有 MZ 头被拦。现在读 ELF `e_machine`（amd64/arm64/386/armv7/riscv64），
与本机 `uname -m` 不符直接拒绝。

**14. 容器里有 `systemctl` 但没有 systemd。**
只判断 `command -v systemctl`，于是 unit 写盘、`systemctl restart` 失败、
脚本以裸退出码结束。现在要求 `/run/systemd/system` 存在**且** `systemctl` 能
真的答出状态（不能只看它的退出码——`degraded` 也是非零，而 VPS 上很常见，
那样会把健康的 systemd 误判成没有）。

**15. 没有回滚路径，下载也没有总超时。**
`install` 直接覆盖旧二进制，配上 `Restart=always`，坏版本只能重下。
现在旧版本留在 `<prefix>/bpb.prev`。下载加了 `--max-time 60`：
只有 `--connect-timeout` 时，半开连接会让脚本在整个 retry 预算里没有任何输出。


### Docker

    docker build -t bpb-native:1.0.2 .
    docker run -d --name bpb -p 8080:8080 -v bpb-data:/data bpb-native:1.0.2

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

### 编译缓存（ccache / sccache）

装了编译器缓存就**自动启用**，不用改命令：

    apt install ccache                        # Debian/Ubuntu（Linux 优先 ccache）
    pacman -S mingw-w64-ucrt-x86_64-sccache   # MSYS2（Windows 优先 sccache）

配置期会打印一行 `compiler cache: ccache at ...` 或 `compiler cache: sccache.exe at ...`；
没装就打印 `compiler cache: none found` 并正常编译。要临时关掉（例如对比纯编译耗时）用
`-DBPB_CCACHE=OFF`。

**Windows 上为什么不是 ccache**：MSYS2 的 ccache 打不开 Windows 风格的编译器路径，
而 CMake 交给 launcher 的正是这种：

```
ccache: error: Could not find compiler "A:\msys64\ucrt64\bin\c++.exe" in PATH
```

同一个编译器写成 POSIX 路径（`/ucrt64/bin/c++.exe`）ccache 就认，但 CMake 递过来的是
反斜杠形式。sccache 是原生 mingw 二进制，直接接受该路径。CI run #38 上 6 个 Windows
job 因此全红、Linux 全绿。所以 `WIN32` 的探测顺序是 `sccache ccache`，其余平台是
`ccache sccache` —— 两边都会回退，只是优先级不同。

命中率实测（`-DBPB_INBOUNDS=vless`，67 个编译单元）：

| 场景 | Linux / ccache | Windows / sccache |
|---|---|---|
| 新目录、空缓存 | 17–18 s | 18 s |
| 新目录、缓存已有同协议 | **1–2 s**（100 %） | **0–1 s**（100 %） |
| 新目录、缓存里只有**另一个协议** | **5 s**（64.8 %） | — |

最后一行是这个项目特别的地方：`BPB_HAVE_*` 是 `add_compile_definitions` 作用在
整个目录上的，所以每个编译单元的命令行都不同；但真正用到这些宏的只有
`main.cpp`、`inbound/registry.cpp`、`inbound/proto/grpc.cpp`、`util/crash.cpp`
四个文件，剩下的照样命中。这也是 CI 里矩阵缓存按架构而不是按协议隔离的原因。

缓存目录用 `CCACHE_DIR` 指定；不指定时是 `~/.cache/ccache`（Windows 是
`%LOCALAPPDATA%\ccache`）。CI 里挂的是 `./.ccache`。

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
| `--cur` | 打印**当前正在运行**的 bpb 实例的隧道域名（Linux 自动发现全部实例：pid/端口/域名/连接状态/数据目录；Windows 构建无隧道，用 `--cur --data <dir> [--port <n>]` 读指定实例） |
| `--passwd [user] <password> [--check]` | 设置 / 查看面板凭据：写 `<data>/passwd`（加盐 SHA-256）。不带参数只看状态并可跟 `--check` 向运行中的面板验证一次 |
| `--res [pid]` | 重启一个正在运行的 bpb（见下） |
| `--log <level>` | 日志级别，默认 `error`（见下） |

### 重启：`bpb --res [pid]`

改完配置、换完二进制之后要重启，但“怎么重启”取决于这个进程是谁拉起来的：
`systemctl restart` 对服务实例有效，对手工跑的实例无效；`kill` 之后手工实例不会自己回来。
`--res` 把这件事收进二进制，由它自己判断：

| 场景 | 行为 |
|---|---|
| 目标由 systemd 管理 | `systemctl restart <unit>` —— 单元文件里的 `Restart=`、环境变量、cgroup 限额全部保留 |
| 目标是手工启动的 | 终止它，然后按**原样的 argv 和原工作目录**重新拉起 |
| 不带 pid | 重启本机 **pid 最小的那个 bpb** |

    bpb --res            # 重启 pid 最小的 bpb（多实例时会先提示找到了几个）
    bpb --res 3249       # 重启指定 pid

实测输出：

    $ bpb --res 3421
      pid 3421: /usr/local/bin/bpb --host 0.0.0.0 --port 8080 --data /root/.bpbdata
      cwd    : /root/.bpbdata
      managed by systemd unit bpb.service -> systemctl restart bpb.service

    $ bpb --res 3490
      pid 3490: /root/bpb.res --host 127.0.0.1 --port 18500 --data /tmp/res-d --log warn
      cwd    : /tmp
      not managed by a service -> terminate and re-exec the same command
      started pid 3500 with the same arguments

几个刻意的取舍：

- **认服务靠 cgroup，不靠 `systemctl status <pid>`**：读 `/proc/<pid>/cgroup`，取最后一个
  `.service` 组件。这不是可选项——`/proc/PID/cgroup` 结尾带换行符，不先 trim 掉，最后一个
  组件就是 `"bpb.service\n"`，判定永远不成立，于是每个服务实例都被当成手工进程。
  （第一次实现就踩了这个，实测后者会绕过 systemd 直接 exec，把 `Restart=` 和 cgroup 全丢掉。）
- **原样重放 argv，不做任何规范化**：操作者的参数是这个实例唯一的描述，`--port 45566 --host 0.0.0.0`
  必须字节级重放，不能“智能”补默认值。
- **子进程三个标准流都接到 `/dev/null`**：只接 stdin 的话，重启后的守护进程仍握着调用方的
  stdout，`bpb --res | tee` 就永远等不到 EOF，看起来像卡死。
- **启动后确认新进程还活着**再报成功：execvp 失败（二进制被删/移动）时立刻退出，
  这时说“started pid N”比报错更糟，操作者会停止排查。
- **pid 不是数字就报错，不退回“最低 pid”**：否则打错一个 pid 会重启另一个无关实例。
- **Windows 上直接拒绝**：没有 `/proc` 读不到别人的 argv，无法按原样重放，
  这与 `--cur` 在 Windows 上需要 `--data` 是同一个原因。
- 终止策略与 systemd 一致：先 `SIGTERM` 等最多 10 秒，不走再 `SIGKILL`。
### 面板图标不依赖外网

面板原先从 `fonts.googleapis.com` 拉 `Material Symbols Rounded`。在 Google 不可达的网络里字体会拿不到，
浏览器就把连字名当普通文字渲染出来（界面上出现 `check_circle`、`settings_backup_restore`、`logout` 这种文字）。

现在字体按面板实际用到的图标做了子集（`assets/fonts/material-symbols-rounded-subset.woff2`，约 6.6 KB），
以 `data:font/woff2;base64` 内联进 `assets/panel/index.html` 与 `assets/login/index.html`，页面里不再有指向 Google 的 `<link>`，
离线/受限网络下图标照常显示。

子集只含页面点名要的图标，所以「新加一个图标却忘了重新生成子集」会原样暴露成连字名文字。
`tools/check_font.py` 就是在检查这件事：它会报出页面用到但子集没有的图标，改完面板跑一次即可：

    python tools/check_font.py       # font: ... / icons used by pages: N / all page icons render
    python tools/build_font.py      # 需要完整的 MaterialSymbolsRounded.ttf，见脚本头注释
    python tools/embed_font.py      # 把 woff2 重新内联进各页面
    python tools/gen_assets.py      # 重生成 src/assets_gen.cpp（装进二进制的内嵌副本）

个别图标（比如「重新生成证书」用的 `restart_alt`）不再走字体，改用**内联 SVG**：
矢量、随字号缩放、用 `currentColor` 跟着按钮的 hover/disabled 状态变色，不占字体子集、也不受字体是否加载成功影响。
新加按钮时优先用这个做法，`<svg class="button-icon" viewBox="0 0 24 24">` 配一条 `path` 即可。

### 查当前隧道域名：`bpb --cur`

重启脚本里常要拿到“这台机器此刻对外的域名”，但域名只存在于运行中的进程状态里。
`--cur` 会扫 `/proc` 找到所有正在跑的 bpb，读出各自的 `--port`/`--data`，然后：

1. 先读数据目录里的 `tunnel-quick.json`（quick tunnel 域名）或 `config.json` 的 `mainDomain`；
2. 再向该实例的 `/<securePath>/panel/tunnel-status` 问一次真实状态，以面板返回的域名为准。

    $ bpb --cur
    pid      port   tunnel domain                                  state
    7754     8080   examinations-widely-occasion-eating.trycloudflare.com   connected   [panel] data=/root/.bpbdata
    6954     18500  (no tunnel)                                    offline      data=/root/.bpbtest18500

面板设了密码也**不影响** `--cur`：命令行有完全权限，直接带上 `X-BPB-CLI` 头去问
`panel/tunnel-status`（见下面「命令行与浏览器的权限怎么分开」），所以状态列是**运行中进程的实时状态**
（`connected` / `offline`）而不是猜的；只有进程没在跑时才退回数据目录里的文件。

这比 `docker logs | grep trycloudflare` 稳：不依赖日志级别（默认 `error` 什么都不打），
也不会把已经退出的旧实例的域名当成当前的。

### 面板密码写在 `.bpbdata/passwd`

老版本把面板密码明文放在 `<data>/settings.json` 的 `pwd` 字段里。问题不只是“明文”，而是
它和一堆别的东西同住一个文件：`settings.json` 是**整份配置**，Telegram token、WARP 私钥、
订阅 token、`securePath` 全在里面，还经常被 `cat` 出来贴进工单、被备份脚本整份拷走、被面板的
`update-settings` 整份回写。密码混在这里，等于跟着一起到处跑。

现在凭据单独一个文件 `<data>/passwd`（POSIX 上 `0600`，只有属主可读；Windows 靠目录 ACL）：

    # user:$sha256$<salt>$<sha256(salt:password)>
    admin$sha256$acfde46f13a6152bb9064acd430fc3fe$ae50bca2714514a0561e47f07345f331b3ce7cd29a808e2fe4c363bf273d358c

加盐 SHA-256 + 常数时间比较，文件泄了也不能直接拿去登录；改密码一条命令，不用起服务、
不用开面板：

    bpb --passwd                     # 看状态：user + 盐长度，不打印任何秘密
    bpb --passwd 'new-pass'          # 设置，用户名取 config.accEmail
    bpb --passwd ops 'new-pass'      # 指定用户名
    bpb --passwd 'new-pass' --check  # 本地校验 + 问一次运行中的面板（accepted / REJECTED）

`--check` 判的**不是**状态码 200：`POST <securePath>/login` 本身也返回 200（登录页 HTML），
所以只认「200 且 `Set-Cookie` 里有 `jwtToken=`」，口令错则由面板回 401。

兼容性：`settings.json` 里已有的明文 `pwd` 仍然能登录，**首次成功登录后自动迁移**成
`passwd`；迁移之后改 `settings.json` 的明文不再生效（`login()` 先看文件）。在面板里改密码
（`update-settings`）会同步重写这个文件，两条路不会打架。忘了密码就 `bpb --passwd <new>`
覆盖 —— 只有数据目录里确实没有 `passwd` 时才会退回 `settings.json` 的明文分支。

### 命令行与浏览器的权限怎么分开

老规则是「回环地址 = 管理员」，凡是从 `127.0.0.1` 进来的请求一律放行。这条规则错在把两种完全不同的
调用方混成了一种，而它们都会落在回环地址上：

- **命令行**（`bpb --cur`、脚本）—— 本来就以操作者身份在机器上跑，应当**全权限、免密、免令牌**；
- **浏览器** —— 不管是本机开的，还是通过 `ssh -L` 端口转发进来的，都必须登录；
- 还有第三个：**本进程自己的隧道**。它把回源连接发到 `127.0.0.1`，所以经隧道进来的请求
  在服务端看起来同样是回环地址 —— 这条旁路等于让整个公网免密进面板。

真正能区分它们的是**浏览器发不出来的东西**：顶层导航（地址栏、点击链接）根本不能带自定义请求头，
而跨源页面想加一个会触发 CORS 预检，这个服务端从不回应预检。所以命令行用 `X-BPB-CLI` 头表明身份：

```bash
curl -H 'X-BPB-CLI: 1' http://127.0.0.1:8080/securepath/panel/settings   # 直接拿到 JSON
```

| 调用方 | 如何获得权限 |
|---|---|
| 命令行 / 脚本 | 回环地址 + `X-BPB-CLI` 头 → **全权限，不需要密码，也没有令牌文件要管** |
| 浏览器 | 登录后拿到 `jwtToken`，签名有效**且**未过期才通过 |

浏览器的会话是**会话 cookie + 10 分钟过期**：

- `Set-Cookie` 不带 `Max-Age`/`Expires`，浏览器一关就丢；
- JWT 里的 `exp = iat + 600`，页签一直开着也最多 10 分钟后失效；
- 面板里任何 `panel/*` 请求拿到 401 都会整体跳回登录页（不用逐个调用点自己处理）。

改密码（`bpb --passwd` 或面板里的「重置」）会轮换 JWT 签名密钥，所有已签发的会话立即作废。

### 状态以磁盘为准，且只在按钮上刷新

面板的状态读数（账号数、WARP 是否就绪、隧道域名）原先全部来自进程启动时抓的那份内存快照。
于是出现两种不一致：

- **注册完成后看到的还是旧账号数**：`/panel/warp-register` 把账号写进文件，但它回给浏览器的
  数量取自内存里的 vector，下一次启动才会真正用上这一批；
- **命令行或手改 settings.json 之后面板毫无反应**，直到重启进程。

现在改成「磁盘是唯一真相」：

| 接口 | 行为 |
|---|---|
| `GET panel/warp-status` | `accounts` 直接数 `settings.json` 里的 `warpAccounts`；另给 `memoryOnly` 暴露内存值，两者不一致时一目了然 |
| `POST panel/warp-register` / `update-warp` | 写盘后立刻 `reload_from_disk()`，回给浏览器的是文件里真实的内容 |
| `POST panel/reload` | 重读 config.json + settings.json，返回与 `panel/settings` 同构的响应 |

`Store::reload_from_disk()` 把内存整个重置后再 load：`load()` 只覆盖文件里存在的键，
于是「文件里是 true、内存里还是 false」的值原来会在下一次保存时被内存覆盖回 false——现在以磁盘为准。
进程事实（监听地址/端口、TLS 端口、证书路径）不在文件里，重载时显式保留，否则会被
`set_listen_facts()` 的 argv 值顶掉。

注意 `kv_` 只接受 `default_kv()` 里已有的键，所以**不在 schema 里的自定义键**重载后不会保留；
这是既有行为，不是这次改的。

**不自动刷新。** 页面上没有任何 `setInterval`：设置区那个图标（`settings_backup_restore`）
原本是「重置面板设置」，现在改成「从磁盘重新读取状态」。点它 = `POST panel/reload` +
重画设置/订阅/客户端列表 + `refreshWarpAndTunnel()`，并弹一句「已从磁盘重新读取」。

实测：

    # 只改文件，内存没动
    accounts=2  memoryOnly=0      <- warp-status 已按磁盘计数
    # 点按钮（POST panel/reload）之后
    accounts=2  memoryOnly=2      <- 内存追平磁盘
    # 文件里删掉的键不会在 save 时复活
    blockAds 是否被写回: False
## 入栈协议与按协议构建

各入栈协议是**独立源文件**，用 CMake 选项选择编哪些，没选中的**不参与编译**
（不是运行时关掉，是根本不进二进制）：

    -DBPB_INBOUNDS=vless                只编 VLESS（连带编入 XHTTP，见下）
    -DBPB_INBOUNDS=vless,trojan         指定组合
    -DBPB_INBOUNDS=all                  全部：六个二进制协议全部编入
    # 配置期会打印运行时列表，并写进 build/expected-inbounds.txt：
    #   -- bpb inbounds: vless,trojan,shadowsocks,vmess,vless-xhttp,vless-grpc

XHTTP 是**传输绑定**而不是独立协议：它的源码跟着 VLESS 一起编，所以 `-DBPB_INBOUNDS=vless`
的启动行是 `inbounds: vless,vless-xhttp`。gRPC 则是独立选项。

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

    bpb native listening on http://0.0.0.0:8080 (secure path: /securepath/, inbounds: vless,trojan,shadowsocks,vmess,vless-xhttp,vless-grpc)

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
| `/<sp>/panel/warp-status` | 出栈状态（后端类型、ready、账号数、是否 dry run、`socks=` 监听状态） |
| `/<sp>/panel/warp-register` | 注册 WARP 账号（**默认 dry run**，返回 `saved:false` 表示未写账号池） |
| `/<sp>/panel/tunnel-status` | 隧道状态：`running/connected/registered`、`hostname`/`url`、`hostnames`（ingress 全部主机名）、`mainDomain`（订阅当前域名） |
| `/<sp>/panel/tunnel-wake` / `tunnel-sleep` | 唤醒 / 休眠（都返回与 status 同构的最新状态） |
| `/<sp>/panel/update-warp` | WARP 账号 |
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

### 隧道回源由进程自己决定，不能手填

面板上曾经同时有「监听端口」和「本地回源地址」两个可编辑框，语义重叠且能互相矛盾：截图里出现
「监听端口 = 8080」而进程实际监听 45566，于是隧道被改成把流量转发到没人监听的端口，
Cloudflare 侧表现为 502/530。现在：

| 字段 | 含义 | 可编辑 |
|---|---|---|
| 对外端口（`directPort`） | 订阅里写的端口。无端口映射时 = 实际监听端口，前面有 NAT 时填映射后的端口 | 是 |
| 对外地址（`directHost`） | 订阅里写的地址。不填时由**请求的 `Host` 头**推断 | 是 |
| 本地回源地址（`cfTunnel.originHost/originPort`） | 隧道把请求转给谁 | **否**，恒为 `127.0.0.1:<实际监听端口>` |

保存时 `originHost`/`originPort` 一律由 `store_.listen_port()` 重算，请求里带什么都忽略；
面板显示的那个值就是推导结果。

### 订阅里的地址是怎么来的

`directHost` / `directPort` 决定订阅里每一条线路的地址。它们有四种来源，优先级从高到低：

1. **面板里手工填的**（或 `config.json` 里非空的）——显式声明，任何请求都不覆盖；
2. **请求的 `Host` 头**——NAT / 端口映射 / 反向代理下，进程自己绑的地址和端口对外都不成立，
   只有浏览器实际用的那个地址是对的。所以每次取订阅都会顺手把它记下来；
3. **监听地址**——启动时由 `set_listen_facts()` 填，绑定 `0.0.0.0` 时是 `localhost`；
4. `localhost`——兜底。

第 2 条有个坑，修过一次：跑过 quick tunnel 的机器会把隧道域名写进 `directHost`，
隧道关掉后这个名字就是死的，而 `direct_host()` 又拒绝发布 `*.trycloudflare.com`，
于是每条订阅都退化成 `localhost:8080`；同时"已经有值就不覆盖"的判断把它当成
手工配置挡住了，**公网地址永远写不进去**。现在 `.trycloudflare.com` 的 `directHost`
被当作「没配过」处理，让请求改正它；隧道模式下仍然发布隧道域名，因为那才是客户端能连的地址。


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

## 传输方式：WebSocket / XHTTP / gRPC

同一个 VLESS 会话可以跑在三种传输上。面板「通用」区有两个开关 **XHTTP** 和 **gRPC**，默认都关；
打开一个就**多生成一份**该传输的配置，WebSocket 那份始终保留 —— 关掉开关不会让客户端没得用，
打开开关也不会顶掉最通用的那一条。订阅里每个主机因此有 `1 + 开着的传输数` 条线路，
备注后缀 ` XHTTP` / ` gRPC` 用来区分。

| 传输 | 开关 | 客户端 streamSettings | 服务端入口 | 适用 |
|---|---|---|---|---|
| WebSocket（始终有） | — | `network:ws` + `wsSettings.path` | `/vl` 升级 | 最通用，**隧道下唯一可用** |
| XHTTP（SplitHTTP） | `enableXHTTP` | `network:xhttp` + `xhttpSettings{path:/vlx, mode:packet-up}` | `GET /vlx/<sid>`（下行）+ `POST /vlx/<sid>/<seq>`（上行） | 长连接被干扰、只放行普通 POST/GET 的网络（**仅直连**） |
| gRPC | `enableGRPC` | `network:grpc` + `grpcSettings{serviceName:vlg}` | `/vlg/Tun`（HTTP/2 bidi stream） | 只放行 HTTP/2 的网络（**仅直连**） |

> ⚠️ **隧道开着时 XHTTP / gRPC 不可用，这是 Cloudflare 边缘的限制，不是本项目的缺陷。**
> 面板会把这两个开关存成 `false`，并在响应里带上 `transportsDisabled` 说明原因。
> 详见[下文](#为什么隧道下没有-xhttp-和-grpc)。

这两个新传输都不是 WebSocket 协议：连接由 HTTP 服务端的钩子接管，而不是走升级流程 ——
`set_takeover` 拿走 XHTTP 的下行 GET，`set_pre_takeover` 在 HTTP/1.1 解析之前认出 `PRI * HTTP/2.0` 前言。

**开关同时管服务端**：关掉 `enableXHTTP` / `enableGRPC` 后，对应入口直接返回 `false`（XHTTP 的请求
落回面板 404，h2 前言不再被接管），旧订阅里残留的地址不会变成一个隐藏入口。订阅生成侧还会再按
`bpb::inbound::all()` 过滤一次：二进制里没编进 `vless-xhttp` / `vless-grpc` 时，开关打开也不会生成。

**面板上报的也是实际能服务的值**，不是 `settings.json` 里那个布尔：一个 `--protocol trojan`
的二进制显示这两个开关为 OFF（它确实没有那两个钩子），而 `--protocol vless` 会显示
`enableXHTTP` 为 ON —— VLESS 是带着 XHTTP 钩子一起编的。存储值不动，换个能用的二进制回来
设置还在。

各客户端支持度不同，生成器按能力取舍：

- **Xray / v2rayN / sing-box raw**：三种都给（share link 为 `type=xhttp&path=/vlx&mode=packet-up`、
  `type=grpc&serviceName=vlg&alpn=h2`）；
- **Clash.Meta / sing-box**：只给 WebSocket + gRPC，**没有 XHTTP**（两者都没有这个传输，写进去只会导入失败）。

客户端支持度也贯穿到 `/sub/raw`：`?app=clash` 和 `?app=sing-box` 的 raw 里不会再出现
`type=xhttp` 的行，否则导入后是一个连不上的节点。

**XHTTP / gRPC 只挂 VLESS。** 这两个传输的服务端钩子把字节流直接交给 `parse_vless()`
（`vless_grpc.cpp`、`vless_xhttp.cpp`），trojan / vmess / ss 客户端拨 `/vlg` 或 `/vlx` 时
字节会被喂给 VLESS 解析器 —— 实测连接建立、服务端接受，然后永久挂住。所以这三个协议
的节点只有 WebSocket。

**sing-box 订阅里没有 Shadowsocks。** 它的 ss outbound 没有 `tls` 也没有 `transport` 字段
（只支持 SIP003 插件），而本项目的 ss 入栈是 WebSocket 封装的。发出去的后果不是那一个节点
失效，而是**整个订阅无法导入**：`FATAL decode config: outbounds[6].tls: json: unknown field "tls"`。
xray 和 Clash.Meta 都支持 ss over ws+tls，各有各的。

### `ss://` 链接曾经全是「延迟 -1」

SIP002 的 URI 只定义 `host`、`port`、`cipher`，**没有任何字段能表达 WebSocket**。
传输方式必须写进 `plugin` 参数，而 v2rayN / sing-box 解析 ss 时只看 `plugin`，
把 `type=`、`host=`、`path=`、`security=` 全部丢掉。之前就是这么发的，结果：

- 导入看起来正常，节点名、地址、端口都对
- 客户端按**裸 TCP Shadowsocks** 去连 `:443`
- 服务端在等 WebSocket 升级，两边都等对方先说话
- 所有测速一律 **延迟 -1（不可达）**

现在改为 `?plugin=v2ray-plugin;mode=websocket;host=<域名>;path=<路径>[;tls];mux=0`。

转义规则只有一个依据——v2rayN 自己的写法和读法：

```
写：pluginArgs += "mode=websocket;"          // key 与 value 之间的 = 不转义
    path.Replace("=", "\=")                 // 只转义 value 内部
读：t.StartsWith("path=")                    // 按裸 = 匹配
    pathValue.Replace("\=", "=")            // 再还原
```

所以**只有 value 内部的 `=` 和 `,` 加反斜杠**，分隔用的 `=` 必须留裸的。
一开始把整个 `key=value` 都转义了，生成 `mode\=websocket`，任何客户端都匹配不上
`mode=`，症状完全相同。

## 为什么隧道下没有 XHTTP 和 gRPC

这两个传输需要**开放式响应流**：XHTTP 的下行是一条永不结束的 `GET`（`text/event-stream`），
gRPC 是一条双向 stream。它们在直连时完全正常（本地 `GET /vlx/<sid>` 返回 `200` +
`Transfer-Encoding: chunked`），但**经 Cloudflare 隧道时客户端一个字节都收不到**。

### 三种组合实测（同一台 1 核 100 MB 小鸡，同一份源站）

| 连接器 | 隧道 | 普通 HTTP | WebSocket | XHTTP 下行 |
|---|---|---|---|---|
| 本项目连接器 | quick tunnel | 302 / 404 正常 | ✅ 可用 | ❌ 000，12 s 超时，0 字节 |
| **官方 cloudflared 2026.10.7** | quick tunnel | 302 / 404 正常 | — | ❌ 000，18 s 超时，0 字节 |
| 本项目连接器 | **命名隧道** | 200 / 404 正常 | ✅ 可用 | ❌ 000，30 s 超时，0 字节 |

原始 TLS 探针量的是「**首字节何时到达**」，不是「连接最终有没有关」：

```
first byte at: never | closed at 12831ms | 0B
```

即 Cloudflare 边缘**从头到尾没有转发这个响应的 HEADERS**。

作为对照，同一个源站上带 `Content-Length` 的响应（面板页 223 KB、404 页 47 KB）都是一秒内到齐；
结束得掉的分块响应也一样。**区别只在于「有没有长度、会不会立刻结束」**。

### 客户端只报一个看不懂的错

xray 那边看到的是：

```
net/http: HTTP/1.x transport connection broken: malformed HTTP response
"\x00\x00\x12\x04\x00\x00\x00\x00..."
```

`00 00 12 04` 是一个 HTTP/2 `SETTINGS` 帧（18 字节 payload：
`MAX_CONCURRENT_STREAMS=256`、`INITIAL_WINDOW_SIZE=65536`、`MAX_FRAME_SIZE=16777215`）。
**这是 Cloudflare 边缘发的，不是本项目发的** —— `src/tunnel/h2.cpp` 发的是
`HEADER_TABLE_SIZE=0 / MAX_CONCURRENT_STREAMS=1000 / INITIAL_WINDOW_SIZE=16MB`，数值对不上。
也就是说边缘在客户端声明 `http/1.1` 的情况下仍然塞了 h2 帧进来。

### 试过但无效的修法

| 尝试 | 结果 |
|---|---|
| 发完 HEADERS 再补一个**零长 DATA 帧**推边缘 | 无效（边缘要 body 字节，不是帧） |
| 让零长 DATA **跳过批量缓冲立即 flush** | 是真实的合理修复，但对本问题无效 |
| 源站在 head 之后**立刻发一个字节** | HEADERS 确实到了（`200` + `text/event-stream`），但流仍不结束，xray 依旧拿不到可用数据 |

### 结论与代码位置

所以 `PUT /panel/update-settings` 在隧道开启时会**强制**把两个开关存成 `false`
（`src/app/app.cpp`，注释里写明了上面这三组实测），并在响应里给出：

```json
{"body": {"transportsDisabled": {"reason": "tunnel", "message": "Cloudflare 隧道会把它当成普通 HTTP/1.1 往返……"}}}
```

面板据此提示，而不是让用户看着一个刚打开就自己弹回去的开关。

要用这两种传输，只能关掉隧道走直连。

## 证书信任：pin 必须跟着每个协议走

自签证书的 CN 是 `localhost`、没有 IP SAN，任何客户端按标准验证都会拒绝：

```
tls: failed to verify certificate: x509: cannot validate certificate for 203.88.113.121
     because it doesn't contain any IP SANs
```

所以每个订阅生成器都必须把证书指纹**明确交给客户端**，而且各家的写法不同：

| 客户端 | 字段 | 类型/位置 |
|---|---|---|
| vless / trojan / ss 分享链接 | `pcs=` | query 参数 |
| vmess 分享链接 | `pinnedPeerCertSha256` | base64 JSON 里的**字符串** |
| xray 配置 | `tlsSettings.pinnedPeerCertSha256` | **字符串**，不是数组 |
| Clash.Meta | 无 pin，用 `skip-cert-verify: true` | — |
| sing-box | 无 pin，用 `tls.insecure: true` | — |

> vmess 的 pin 写成数组会让 xray 直接启动失败：
> `json: cannot unmarshal array into Go struct field ... of type string`。

这是**订阅能否连通**的分水岭，不是可选的加固：pin 一漏，那条线路就是
「导入成功、拨号时 x509 失败」，而客户端界面上只有一个红叉。

## 传输实现要点（踩坑记录）

- **gRPC 的消息体不是裸字节**：每条 message = `1B 压缩标志 + 4B 大端长度 + protobuf Hunk{0A varint(data)}`，
  剥离后才是 VLESS 字节流；发送方向同样要包成 Hunk。message 边界与协议边界无关，必须当字节流重拼。
- **gRPC 结束必须发 trailing HEADERS + `grpc-status: 0` + END_STREAM**，否则客户端报
  server closed the stream without sending trailers，即使数据已经传完。
- **一条 TCP 要承载多条 stream**（一个 stream 一个会话）。`MAX_CONCURRENT_STREAMS` 给小了会让客户端
  排队而不是报错，表现为莫名卡死；本项目设 256。
- **HPACK**：服务端宣告 `SETTINGS_HEADER_TABLE_SIZE=0` 可以合法关掉动态表，但 Huffman 解码躲不掉；
  位流不足时不能当成输入结束（首个实现就因此在字节边界截断 `:path`，客户端一路 404）。
- **XHTTP 的 seq 会乱序**（HTTP/2 下每 chunk 一个 goroutine）：按 seq 重排、重复 seq 丢弃、同一会话只允许一个下行 reader；
  POST 可能先于 GET 到达，必须先缓冲。
- **会话生命周期与 TCP 连接解耦**：客户端会复用连接（默认 3 条、每条几百次请求），一条连接断开不等于会话结束。
- **PING 必须原样回 8 字节 payload**：不回，客户端 BDP 不增长，吞吐锁死在 64 KB/RTT。
- **XHTTP 的每会话成本比 WebSocket 高一个数量级**（实测 1018 kB vs 82 kB）：它要同时持有下行 GET、
  乱序缓存和上行队列。gRPC 则相反，一条 TCP 承载全部 stream，30 并发只多 100 kB。
  开关本身不花内存，真正花钱的是流量真的走上去之后。


## WARP 出口

出口就是把 VLESS 会话的上游连接接进 WARP：进程内用户态 TCP/IP 栈直连 WireGuard，
不需要外部程序也不需要 `NET_ADMIN`。

另有 **侧车容器**（整机出网，需 `NET_ADMIN`）：

    docker run --rm -v "$PWD/data:/data" -v "$PWD/warp:/out" bpb-native:1.0.2 \
      --export-warp /out/wg0.conf --data /data
    docker compose -f docker-compose.warp.yml up -d --build

侧车不用 `wg-quick`（普通容器写不了 `/proc/sys`、也跑不了 `resolvconf`），
而是手工 `wg setconf` + 地址 + 路由，让面板容器共享它的网络命名空间。

### 账号池不预置任何账号

`warpAccounts` 曾经在 `warps_.empty()` 时回落到两条写死的 WARP 注册。它们早已失效，但看起来
就像一份可用账号池：握手永远不完成，出栈一直是关的，每条连接静静退回直连 socket，而面板照样显示
「WireGuard 已启用」。现在**默认就是空数组**：

- 打开开关时若账号池为空，保存**直接拒绝**（`success:false`，`wgOutbound.enabled` 保持 `false`），
  面板弹「需要先注册 WARP 账号」，并说明开关已保持关闭；
- `start_wg_outbound()` 也据实报错，不再假成功。

所以 `warp=off` 现在只有一个解释：账号池是空的，去点一下「续期」/「注册」。

### 出栈怎么用

隧道起来之后，除了入栈代理会自动把境外流量送进 WARP，还给本机留了一个
SOCKS5 端点（`wgOutbound.bindHost` + `wgOutbound.socksPort`，默认
`127.0.0.1:11080`）：

```bash
curl --socks5-hostname 127.0.0.1:11080 https://www.cloudflare.com/cdn-cgi/trace
# ip=104.28.x.x  warp=on
```

只实现 `CONNECT`：隧道里只有 lwIP 的 TCP，`BIND` 与 `UDP ASSOCIATE` 一律回
`0x07`。握手没成功时端口根本不会打开，`warp-status` 的 `socks=` 字段会说
`stopped` —— 「配了却连不上」和「没配」必须能分开。
### 面板里的注册（默认 dry run）

`warpRegisterDryRun` 默认 **`true`**：

- **dry run**：生成 X25519 密钥对、构造请求体、打印日志，返回**合成账号**，
  响应里 `saved:false`，**完全不联网**
- 关掉之后才会真正 `POST api.cloudflareclient.com` 并写入账号池

之所以默认 dry run：Cloudflare 对注册接口按来源 IP 限流，开发和演示不该消耗配额。
另外 dry run **绝不写账号池** —— 合成账号没有可用密钥，写进去会让下次启动拿到一个死账号。

### 内置用户态 WireGuard

| 目录 | 内容 |
|---|---|
| `src/wg/` | Noise_IKpsk2 握手与传输封装：X25519、HKDF-HMAC-BLAKE2s、ChaCha20-Poly1305、TAI64N、mac1 |
| `src/net/wg_stack` | 内嵌 lwIP 用户态 TCP/IP 栈，`nif->output` 直连 WireGuard 传输层 |
| `third_party/lwip` | 裁剪到 core + IPv4 的 lwIP（BSD 许可） |

账号同样复用 `warpAccounts[0]`，不重复注册。

实测（1 核 / 512 MB）：

| 项目 | 结果 |
|---|---|
| 连通性 | 连续 10 次 HTTPS 经 VLESS → bpb → WARP 全部成功，出口均为 WARP 地址，平均 1.5 秒；100 KB 下载完整 |
| 常驻内存 | 单进程约 2.4 MB，无第二个进程

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

9. **`wgOutboundSocks` 是个空承诺**：`bindHost` / `socksPort` 从第一版就写在设置里，
   面板把两者拼成 `wgOutboundSocks` 回显，但**从来没有任何代码监听那个端口**。
   `warp-status` 说 `ready=true`，`curl --socks5 127.0.0.1:11080` 却是
   `Connection refused` —— 配了却不能用，比没配更误导。
   现在 `src/net/wg_socks.cpp` 在握手成功后才起 listeners（握手失败立刻关掉，
   不留一个接受连接却拒绝的中转站），只实现 CONNECT：隧道里只有 lwIP 的 TCP，
   BIND 与 UDP ASSOCIATE 回 `0x07`。吊销路径同样接上 `stop_wg_outbound()`。

10. **隧道里 `Host` 永远是回源地址**：CF edge 把公网域名放在 HTTP/2 的 `:authority`
   伪头里，而回源循环的第一行就是 `if (k[0] == ':') continue`，把这个伪头一起丢了。
   源站于是只看到 `OriginStream` 从 `cfg.originHost` 补的 `Host: 127.0.0.1:8080`，
   凡是判断"我现在被谁访问"的逻辑全错 —— 最直接的表现是面板二维码在隧道模式下对
   自己的公网 URL 返回 **404**（同源校验拿公网域名去比 `127.0.0.1`）。
   修法是**在跳过伪头之前**先把 `:authority` 还原成 `Host`，cloudflared 也是这么做的。
   顺序很关键：写在循环末尾等于没写，因为 `continue` 已经跳过了。

11. **`MemoryMax` 和进程里的预算各说各话**：unit 里是常量 40M，`relayPoolBudgetMb`
    却是独立的一份，两者毫无关系。100 MB 的小鸡上一波下载正好把 40M 撑满，
    systemd 直接 OOM 杀掉整个进程 —— 一次断掉**所有**会话，而不是拒绝最新的那个。
    现在上限只有一个来源：`bpb --mem-default`（默认 64）→ 安装脚本写进 unit 和
    `ExecStart --mem-max` → 进程再把中继池夹到它的一半（`src/util/memlimit.h`）。
    改上限只改一处，`--mem-max N` 在写任何文件**之前**校验（24..65536），
    否则一个 `64MB` 的手误会先换掉二进制再报错。

## 性能实测

测试链路：**本机 curl --proxy → bpb 的 VLESS → WARP 出栈 → GitHub**，
`cloudflare.com/cdn-cgi/trace` 返回 `warp=on` 确认流量确实经过 bpb。服务端每秒采样
`/proc/<pid>/status`。机器为 1 核 / 469 MB。

### 内存预算：并发准入 + 动态缓冲

数据面有两道硬闸，都实现在 `src/util/budget.h`，都可以在面板里改，改完立刻生效
（`settings.json` 的 `relayMaxSessions` / `relayInitialBufferKb` / `relayMaxBufferKb` /
`relayPoolBudgetMb`，面板的 WARP 页下方四个数字框）：

| 闸门 | 默认 | 作用 |
|---|---:|---|
| 活跃会话上限 | 40 | 准入发生在**升级 101 之前**，超限直接回 `503` + `Retry-After: 1`，不建线程、不建缓冲 |
| 每方向初始缓冲 | 50 KiB | 会话起来时的读写缓冲，40 个会话约 4 MB 应用层占用 |
| 单连接缓冲上限 | 400 KiB | 只有"读满一整块"才翻倍扩容，连续翻到上限为止 |
| 缓冲池总预算 | 8 MiB | 全局计数器，扩容前先扣额度，扣不到就不扩 |

扩容规则是"读满了才长"：一次只读到半块说明这条流本来就跟得上，给它更大的缓冲只会
白占配额。所以小请求和小文件始终停在 50 KiB，只有真正被窗口卡住的大文件流才会长到
400 KiB —— 吞吐由窗口决定，内存由并发数和池预算决定，两者解耦。

`/panel/relay-status` 直接给出这几个计数（`active` / `rejected` / `poolUsed` /
`poolLimit`），面板和测试脚本读的是同一份数据。

服务层还有一道兜底：systemd 单元里的 `MemoryHigh` / `MemoryMax`。它只是 backstop，
正常工作限额由上面的池预算控制 —— 让 cgroup 先触发回收，而不是直接 OOM 杀掉进程
（那会同时断掉所有会话，而不是只拒绝最新的那个）。

这两个数字和进程里的预算**曾经是两套互不相干的常量**：unit 写着 40M，而中继预算根本不
知道有这个上限。在 100 MB 的小鸡上，一波下载正好撞到 40 MB，systemd 的回答是

```
bpb.service: A process of this unit has been killed by the OOM killer.
bpb.service: Failed with result 'oom-kill'.
```

结果不是拒绝最新的那一个连接，而是**一次杀掉所有会话**。现在两者是同一个数：

| 位置 | 来源 |
|---|---|
| unit 的 `MemoryMax` | `bpb --mem-default`（默认 64）或安装脚本的 `--mem-max N` |
| unit 的 `MemoryHigh` | `MemoryMax` 的 85%（下限 24） |
| 进程的 `--mem-max` | 安装脚本把同一个数字写进 `ExecStart` |
| 中继缓冲池 | `configure_relay_budget()` 把它夹到上限的 **一半**，超了打一条 warn |

`/panel/relay-status` 里的 `memoryLimitBytes` 就是进程实际拿到的那个数，可以直接和
`systemctl show bpb -p MemoryMax` 对照。

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

### 隧道数据面吞吐与 CPU（全链路）

链路：客户端 → Cloudflare 边缘 → 隧道 → 本机 origin（回环 http.server），客户端也用 xray 跑在
同一台机上，所以客户端与服务端共享 1 核，绝对值偏低、比值可信。

| 栈 | 单流 100 MB | 4 并流 | 每 GB CPU |
|---|---:|---:|---:|
| cloudflared + xray（命名隧道） | 44 MB/s | 9.5 MB/s | 7.4 / 9.5 s |
| bpb 修复前（quick 隧道） | 16~21 MB/s | — | **32.9~35.7 s** |
| **bpb 修复后（quick 隧道）** | **47.1 MB/s** | **31.8 MB/s** | **5.2 / 5.8 s** |

这台机的裸链路（直连测，不经隧道）是 `48.6~48.8 MB/s`（Cloudflare speed test）、`53.7 MB/s`（cachefly），
所以 **单流 47.1 MB/s 已经是线速的 96%**，此时 bpb 只占 24% 的一个核 —— 瓶颈回到链路上。

三个改动（都在隧道数据面）：

1. **二次方拷贝**：`client.cpp` 的抽水循环只在循环外检查一次高水位，回环源站可以一直读，
   `toEdge` 队列涨到 MB 级；之后每写 16 KB 就 `erase(begin, begin+off)` 把整个尾巴前移。
   `perf` 显示 **74% 的周期在 libc 的 memcpy 循环**，一次 100 MB 下载产生几十 GB 无效拷贝。
   改成每轮复检高水位 + 摊还压缩（消费过半才压缩）。
2. **h2 连接级接收窗口**：`SETTINGS_INITIAL_WINDOW_SIZE` 只管**流**窗口，连接窗口按协议固定从
   65 535 开始、只能靠 `WINDOW_UPDATE` 增长；原来每个 DATA 帧还一次信用，连接窗口永远只有一个帧，
   等于“每 RTT 飞 64 KB”。现在建连先 `WINDOW_UPDATE(0, 4 MB)`，之后按 1 MB 批量还信用。
3. **去掉每帧开销**：收帧复用缓冲（原来每 DATA 帧一次 `std::vector` 分配，100 MB ≈ 6400 次）、
   帧头与载荷合并成一条 TLS 记录（原来一帧两次 `SSL_write`）、源站读块 16 KB → 64 KB。

复现方式见 `TESTS.md` 第 10 节；定位手法：`perf record -g -p <pid>` 看热点，`perf stat -e syscalls:sys_enter_sendto` 看每次系统调用搬多少字节（修复前只有约 2.4 KB）。


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

## Windows 构建的两个坑

### 不要把自己的 `FILE*` 交给 OpenSSL

Windows 上 OpenSSL 是独立 DLL，和 exe 不共享 CRT。`PEM_write_X509(FILE*, …)` /
`PEM_read_X509(FILE*, …)` 会走 `OPENSSL_Uplink` 回调，没有安装 Applink 时进程直接崩：

    OPENSSL_Uplink(00007FFB56A12910,08): no OPENSSL_Applink

表现很迷惑：`tls-cert.pem` 是 0 字节，进程在监听之前就没了，日志只有这一行。
现在证书读写全部走内存 BIO（`PEM_write_bio_X509` / `PEM_read_bio_X509`），
文件用 `std::ofstream` 自己写，不跨 CRT 传递流对象。

### 图标子集缺图不会报错，只会显示成文字

见「面板图标不依赖外网」。`tools/check_font.py` 是唯一能提前发现的检查，
加图标后务必跑一遍；新按钮更稳的做法是直接用内联 SVG。

## 架构

    src/inbound  入栈注册表 + 每协议一个源文件（vless/trojan/shadowsocks/vmess）
    src/inbound/proto  <协议>_ws.cpp：WS 帧编解码、握手、协议帧、双向转发
    src/net      套接字、poll/WSAPoll 封装、HTTPS 客户端（支持 CONNECT 代理）、TLS 流
    src/http     HTTP/1.1 服务（keep-alive、WebSocket 升级）
    src/proxy    会话配置与前向声明；各入栈实现见 src/inbound/proto/*
    src/tunnel   内置 Cloudflare Tunnel 客户端：capnp / HTTP/2 / RPC / 回源 / 监督重连
    src/sub      xray / sing-box / clash / raw / wireguard 订阅生成，WARP 注册
    src/settings JSON 设置存储（原子写）；面板凭据 <data>/passwd（命令行不需要凭据）
    src/app      路由、面板接口（每条请求都验证）、DoH、Telegram
    src/app/qrcode.{h,cpp}  二维码：PNG 编码 + 同源校验，整条路由自己持有一个文件
    src/util/memlimit.{h,cpp} 内存上限（--mem-max / --mem-default / 中继池夹取）
    src/crypto   SHA-224/256、HMAC、HS256 JWT
    src/util     日志、崩溃处理、中继内存预算（budget）、内存上限（memlimit）
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

### 构建缓存

每个 job 都有一步 `Restore compiler cache`（`actions/cache@v4` + 编译器缓存）：

| job | 工具 | 缓存键 | 落盘位置 |
|---|---|---|---|
| `linux` | ccache | `ccache-linux-<arch>-<协议>-<sha>` | `./.ccache`，bind-mount 进容器的 `/src/.ccache` |
| `linux-all` | ccache | `ccache-linux-<arch>-all-<sha>`，回退键含 `ccache-linux-<arch>-` | 同上 |
| `windows` | sccache | `sccache-windows-x86_64-<协议>-<sha>` | `C:\sccache`（**必须是 Windows 路径**） |

回退键故意写得比主键宽：同协议的同架构缓存最好，其次是**同架构的任意协议**缓存
（实测换协议仍能吃到 64.8% 命中），最后才从零开始。这不是猜的——用
`BPB_HAVE_*` 的只有四个文件，大部分编译单元跨协议完全相同。

Windows 那边有个坑：`SCCACHE_DIR` 必须是 **Windows 路径**（`C:/sccache`）。写成 MSYS 的
`/c/sccache` 时 sccache 不报错，而是**静默回落到 `%LOCALAPPDATA%`**，缓存动作于是存了个
空目录（实测 sccache 0.19.0）。

对象文件仍然建在容器内的 `/tmp/b` 并随容器丢弃；存进缓存的是 ccache 自己的
压缩产物，所以 `actions/cache` 存的是 `./.ccache` 而不是 `build/`。

**不产出也不发布容器镜像。**

## 许可证

GPL-3.0，与上游一致。面板 HTML/CSS/JS 资源来自上游项目。