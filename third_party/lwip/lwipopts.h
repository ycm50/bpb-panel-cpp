#ifndef LWIPOPTS_H
#define LWIPOPTS_H

/* Minimal lwIP configuration for a single userspace WireGuard tunnel. */

#define NO_SYS                          1
#define LWIP_SOCKET                     0
#define LWIP_NETCONN                    0
#define SYS_LIGHTWEIGHT_PROT            0

#define MEM_LIBC_MALLOC                 1
#define MEMP_MEM_MALLOC                 1
#define MEM_ALIGNMENT                   8

#define LWIP_IPV4                       1
#define LWIP_IPV6                       0
#define LWIP_IPV6_ND                    0
#define LWIP_IPV6_SEND_ROUTER_SOLICIT   0
#define LWIP_IPV6_AUTOCONFIG            0
#define LWIP_ICMP                       0
#define LWIP_ICMP6                      0
#define LWIP_RAW                        0
#define LWIP_DHCP                       0
#define LWIP_AUTOIP                     0
#define LWIP_ARP                        0
#define LWIP_ETHERNET                   0
#define LWIP_DNS                        0
#define LWIP_UDP                        1
#define LWIP_TCP                        1
#define LWIP_CALLBACK_API               1
#define LWIP_NETIF_API                  0
#define LWIP_NETIF_LOOPBACK             0
#define LWIP_NETIF_HOSTNAME             0
#define LWIP_NETIF_STATUS_CALLBACK      0
#define LWIP_NETIF_LINK_CALLBACK        0
#define LWIP_STATS                      0
#define LWIP_STATS_DISPLAY              0
#define LWIP_SINGLE_NETIF               1
#define LWIP_TIMERS                     1
#define LWIP_NETIF_TX_SINGLE_PBUF       1
#define LWIP_TCP_PCB_NUM_EXT_ARGS       0

#define TCP_MSS                         1240

/* Window sizes are the throughput ceiling of anything carried over WARP.
 *
 * A TCP connection can only have TCP_WND bytes in flight, so its throughput is
 * TCP_WND / RTT. 52*MSS keeps the window under 65535 so no window scaling is
 * needed (lwIP rejects TCP_WND > 0xFFFF without LWIP_WND_SCALE).
 *
 * WINDOW SCALING WAS TRIED AND REVERTED. The theory was that a ~100 ms round
 * trip through the WARP userspace stack capped a single stream at
 * 64480 / 0.103 = 626 KB/s, and a WARP download did sit at ~630 KB/s. But after
 * enabling LWIP_WND_SCALE with TCP_WND = 1024*MSS, the same download measured
 * 631385 B/s -- unchanged to within 0.4% -- while the process never exceeded
 * 10 MB RSS and the relay pool stayed empty. A window that is genuinely the
 * bottleneck gets filled; this one was never used. The ~630 KB/s was the
 * download source rate-limiting the Cloudflare egress IP, not the stack.
 * Do not re-raise these without a source that is known not to throttle.
 *
 * TCP_SND_BUF is the same knob for the upload direction. Uploads measured
 * 21~22 MB/s with 16*MSS, so the send side was already ahead; it is raised to
 * match so the two directions behave alike. */
#define TCP_SND_BUF                     (52 * TCP_MSS)
#define TCP_WND                         (52 * TCP_MSS)
#define TCP_SND_QUEUELEN                (4 * TCP_SND_BUF / TCP_MSS)
#define MEMP_NUM_TCP_PCB                32
#define MEMP_NUM_TCP_PCB_LISTEN         4
/* lwIP's sanity checks against MEMP_NUM_TCP_SEG / PBUF_POOL_SIZE are compiled
 * out because MEMP_MEM_MALLOC=1 (segments and pbufs come from the heap). */
#define MEMP_NUM_TCP_SEG                256
#define PBUF_POOL_SIZE                  32
#define PBUF_POOL_BUFSIZE               1600

#define LWIP_CHKSUM_ALGORITHM           3
#define CHECKSUM_GEN_IP                 1
#define CHECKSUM_GEN_TCP                1
#define CHECKSUM_CHECK_IP               1
#define CHECKSUM_CHECK_TCP              1

#define LWIP_RAND()                     ((u32_t)rand())
#define LWIP_NO_UNISTD_H                1

#endif
