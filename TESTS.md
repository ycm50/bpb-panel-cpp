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

## 2b. 路由与重定向

- `GET /`、`GET /securepath`、`GET /securepath/` -> 302 到 `/securepath/panel`
- `GET /securepath/panel` -> 200（未设密码）或 302 到 login（已设密码）
- `GET /nope` -> 404，页面显示中文"出错了"与提示信息（不能出现 __ERROR_MESSAGE__ 字样）

## 3. 数据面

VLESS 与 Trojan over WebSocket 必须能转原生 TCP。最小验证：

- 用 VLESS 头（版本 0、UUID、cmd=1、端口、atyp=1、IPv4）再拼一个普通 HTTP 请求作为载荷，
  发到 /vl/<任意>，返回帧里应包含 HTTP 响应；
- 用 56 字节 SHA-224 十六进制前缀 + CRLF + cmd + atyp/地址/端口 发到 /tr/<任意>，同上。

## 4. TLS

    ./build/bpb --port 8443 --data ./data --tls-cert cert.pem --tls-key key.pem

- https 访问 /securepath/login -> 200
- 用 http 访问该端口 -> 被拒绝
- wss 上带 VLESS 头 -> 数据面正常

## 5. WARP 出口

    docker run --rm -v "$PWD/data:/data" -v "$PWD/warp:/out" bpb-native:1.0.0 \
      --export-warp /out/wg0.conf --data /data
    docker compose -f docker-compose.warp.yml up -d --build
    docker exec bpb-warp wg show

预期：有 latest handshake，transfer 计数增长；在面板容器内执行 --fetch http://api.ipify.org/
应返回 Cloudflare WARP 的地址。

## 6. 资源占用

    docker stats --no-stream bpb

预期：镜像约 7.5 MB，空载内存 1.5 ~ 2 MB，压测峰值约 4 MB。

## 7. 多架构二进制

CI 会为 amd64 / arm64 / armv7 / 386 / riscv64 各产出一个静态二进制。本地验证某一架构可执行：

    docker run --rm -v "$PWD:/w" -w /w --platform linux/arm/v7 alpine:3.22 ./bpb-linux-armv7 --help

（需要宿主机装好 qemu-user 的 binfmt，或在 CI 里跑。）