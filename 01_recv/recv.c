
#include<rte_eal.h>
#include<rte_ethdev.h>
#include<rte_mbuf.h>

#include<stdio.h>
#include<arpa/inet.h>


#define NUM_MBUFS (4096 - 1)

#define BURST_SIZE 32

int gDpdkPortId = 0; //网络适配器 网卡

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};

static void ng_init_port(struct rte_mempool *mbuf_pool) {
    uint16_t nb_sys_ports = rte_eth_dev_count_avail();
    if(nb_sys_ports == 0) {
        rte_exit(EXIT_FAILURE, "No Support eth found\n");
    }

    //在没有配置DPDK前获取eth0的信息
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(gDpdkPortId, &dev_info);

    const int num_rx_queues = 1;
    const int num_tx_queues = 1;
    struct rte_eth_conf port_conf = port_conf_default;

    rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);
    //启动一个读rx队列
    if(rte_eth_rx_queue_setup(gDpdkPortId, 0, 128, rte_eth_dev_socket_id(gDpdkPortId),
                            NULL, mbuf_pool) <0 ){
        rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
    }
    //启动一个写tx队列
    if(rte_eth_tx_queue_setup(gDpdkPortId, 0, 128, rte_eth_dev_socket_id(gDpdkPortId),
                            NULL, mbuf_pool) <0 ){
        rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
    }
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
    rte_memcpy(eth->s_addr.addr_bytes, src_mac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
}

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

    ng_init_port(mbuf_pool);

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
                    (struct rte_udp_hdr *)((unsigned char*)iphdr + sizeof(struct rte_ipv4_hdr));
                if(ntohs(udphdr->src_port) == 9000) { //端口过滤
                    uint16_t length = ntohs(udphdr->dgram_len);
                    *((char*)udphdr + length) = '\0';

                    struct in_addr addr;
                    addr.s_addr = iphdr->src_addr;
                    printf("src: %s:%d, ",inet_ntoa(addr), ntohs(udphdr->src_port));

                    addr.s_addr = iphdr->dst_addr;
                    printf("dst: %s:%d,length:%d---> %s\n",inet_ntoa(addr), ntohs(udphdr->src_port),
                        length, (char*)(udphdr + 1));
                }
                
                
                rte_pktmbuf_free(mbufs[i]);
            }
        }
    }
}