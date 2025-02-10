#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")

int detector(struct xdp_md *ctx) {
    // Get pointers to the packet start and end
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Check that the Ethernet header is within packet bounds
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Check for IPv4 (ETH_P_IP) packets
    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
        bpf_printk("detector: IP packet detected\n");
    } else {
        // Log non-IP packets along with the EtherType
        bpf_printk("detector: non-IP packet detected, EtherType=0x%04x\n", eth->h_proto);
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
