
#include<rte_eal.h>
#include<rte_ethdev.h>
#include<rte_mbuf.h>

#include<stdio.h>
#include<arpa/inet.h>


#define ENABLE_SEND 1

#define NUM_MBUFS (4096 - 1)

#define BURST_SIZE 32

int gDpdkPortId = 0; //网络适配器 网卡

#if ENABLE_SEND

// IP
static uint32_t gSrcIp;
static uint32_t gDstIp;

// ETH
static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
static uint8_t gDstMac[RTE_ETHER_ADDR_LEN];

// TCP/UDP
static uint16_t gSrcPort;
static uint16_t gDstPort;

#endif

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};

static void z_init_port(struct rte_mempool *mbuf_pool) {
    uint16_t nb_sys_ports = rte_eth_dev_count_avail();
    if(nb_sys_ports == 0) {
        rte_exit(EXIT_FAILURE, "No Support eth found\n");
    }

    //在没有配置DPDK前获取eth0的信息
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(gDpdkPortId, &dev_info);

    const int num_rx_queues = 1;
#if ENABLE_SEND
    const int num_tx_queues = 1;
#else
    const int num_tx_queues = 0;
#endif 

    struct rte_eth_conf port_conf = port_conf_default;

    rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);
    //启动一个读rx队列
    if(rte_eth_rx_queue_setup(gDpdkPortId, 0, 1024, rte_eth_dev_socket_id(gDpdkPortId),
                            NULL, mbuf_pool) < 0 ){
        rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
    }

#if ENABLE_SEND
    //启动一个写tx队列
    struct rte_eth_txconf txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.rxmode.offloads;
    if(rte_eth_tx_queue_setup(gDpdkPortId, 0, 1024, rte_eth_dev_socket_id(gDpdkPortId),
                            &txq_conf) < 0 ){
        rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
    }

#endif 

    //启动网卡
    if(rte_eth_dev_start(gDpdkPortId) < 0 ){
        rte_exit(EXIT_FAILURE, "Could not start\n");
    }

    rte_eth_promiscuous_enable(gDpdkPortId);
}

static void create_eth_ip_udp(uint8_t *msg,size_t total_len, uint8_t *dst_mac, uint32_t src_ip,
    uint32_t dst_ip, uint16_t src_port, uint16_t dst_port) {
    
    struct rte_ether_addr src_mac;
    
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

    rte_eth_macaddr_get(gDpdkPortId, &src_mac);
    rte_memcpy(eth->s_addr.addr_bytes, &src_mac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
}

#if ENABLE_SEND

static void z_encode_udp_pkt(uint8_t *msg, unsigned char *data, uint16_t length) {

    //1 ether
    struct rte_ether_hdr *eth = (struct rte_ether_hdr*)msg;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
    
    //2 iphdr
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr*)(msg + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(length - sizeof(struct rte_ether_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64; //TTL
    ip->next_proto_id = IPPROTO_UDP;
    ip->src_addr = gSrcIp;
    ip->dst_addr = gDstIp;

    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);
    
    //3 udp
    struct rte_udp_hdr *udp = (struct rte_udp_hdr*)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    udp->src_port = gSrcPort;
    udp->dst_port = gDstPort;
    uint16_t udplen = length - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
    udp->dgram_len = htons(udplen);

    rte_memcpy((uint8_t*)(udp + 1), data, udplen);

    udp->dgram_cksum = 0;
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

    return 0;
}

static struct rte_mbuf * z_send(struct rte_mempool *mbuf_pool, uint8_t *data, uint16_t length ) {
    //从内存池中申请内存
    const unsigned total_len = length + 42;
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if(!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc failed\n");
    }
    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;

    uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

    z_encode_udp_pkt(pktdata, data, total_len);

    return mbuf;
}
#endif


int main(int argc, char *argv[]) {

    //检测DPDK的环境是否正确
    if(rte_eal_init(argc,argv) < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL init\n");
    } 

    //创建内存池
    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS, 
            0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if(mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
    }

    z_init_port(mbuf_pool);

#if ENABLE_SEND
    rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)gSrcMac);
#endif

    while(1) {
        struct rte_mbuf *mbufs[BURST_SIZE];// 内存池

        unsigned num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE);
        if(num_recvd > BURST_SIZE) {
            rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
        }
        unsigned i = 0;
        for(;i < num_recvd; i++) {
            struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i],struct rte_ether_hdr*);
            
            //判断类型是否为IPV4
            if(ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                continue;
            }

            struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, 
                sizeof(struct rte_ether_hdr));
            //判断协议是否为UDP
            if(iphdr->next_proto_id == IPPROTO_UDP){
                struct rte_udp_hdr *udphdr = 
                    (struct rte_udp_hdr *)(iphdr + 1);
                
#if ENABLE_SEND
                rte_memcpy(gDstMac, ehdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

                rte_memcpy(&gSrcIp, &iphdr->dst_addr, sizeof(uint32_t));
                rte_memcpy(&gDstIp, &iphdr->src_addr, sizeof(uint32_t));

                rte_memcpy(&gSrcPort, &udphdr->dst_port, sizeof(uint16_t));
                rte_memcpy(&gDstPort, &udphdr->src_port, sizeof(uint16_t));
#endif 

                if(ntohs(udphdr->src_port) == 9000) { //端口过滤
                    uint16_t length = ntohs(udphdr->dgram_len);
                    *((char*)udphdr + length) = '\0';

                    struct in_addr addr;
                    addr.s_addr = iphdr->src_addr;
                    printf("src: %s:%d, ",inet_ntoa(addr), ntohs(udphdr->src_port));

                    addr.s_addr = iphdr->dst_addr;
                    printf("dst: %s:%d,length:%d---> %s\n",inet_ntoa(addr), ntohs(udphdr->dst_port),
                        length, (char*)(udphdr + 1));
#if ENABLE_SEND
   
                    struct rte_mbuf *txbuf = z_send(mbuf_pool, (char *)(udphdr + 1), length);
                    rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1);
                    rte_pktmbuf_free(txbuf);
#endif
                }
                
                rte_pktmbuf_free(mbufs[i]);
            }
        }
    }
}