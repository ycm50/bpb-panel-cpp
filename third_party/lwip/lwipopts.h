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
#define TCP_SND_BUF                     (16 * TCP_MSS)
#define TCP_WND                         (16 * TCP_MSS)
#define TCP_SND_QUEUELEN                (4 * TCP_SND_BUF / TCP_MSS)
#define MEMP_NUM_TCP_PCB                32
#define MEMP_NUM_TCP_PCB_LISTEN         4
#define MEMP_NUM_TCP_SEG                128
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
