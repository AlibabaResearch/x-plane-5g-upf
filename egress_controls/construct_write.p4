#ifndef _CONSTRUCT_WRITE_
#define _CONSTRUCT_WRITE_

#include "../include/types_r.p4"
#include "../include/configuration.p4"

control ConstructWrite(inout headers_t hdr, inout eg_metadata_t meta) {
    apply {
        /* Chosen RDMA Server MAC Address */
        hdr.ethernet.dst_addr_1 = meta.mirror_truncate.server_mac_addr_1;
        hdr.ethernet.dst_addr_2 = meta.mirror_truncate.server_mac_addr_2;
        /* Fake MAC Address as source */
        hdr.ethernet.src_addr = 0x000000000001;

        /* Static RDMA Client IP Address where the connection is opened */
        hdr.ipv4.src_addr = RDMA_IP;//RDMA_IP;
        /* Chosen RDMA Server IP Address */
        hdr.ipv4.dst_addr = meta.mirror_truncate.server_ip_addr; 
		hdr.ipv4.ttl = 64;
        hdr.ipv4.flags = 0x2;
        hdr.ipv4.protocol = ipv4_protocol_t.UDP;
        /* Set base IPv4 len, will be updated with payload and padding in Egress */
        hdr.ipv4.total_len = hdr.ipv4.minSizeInBytes() + hdr.udp.minSizeInBytes() + 
                        hdr.ib_bth.minSizeInBytes() + hdr.ib_reth.minSizeInBytes() + 4 + 
                        hdr.ue_flow_key.minSizeInBytes() + hdr.ue_flow_rule.minSizeInBytes(); 

        /* Invalidate TCP header ([lyz]:assume only UDP packets for now), it'll be replaced with UDP/IB */
        hdr.udp.setValid();
        hdr.udp.src_port = 0;
        hdr.udp.dst_port = UDP_PORT_ROCEV2;
        hdr.udp.checksum = 0;

        /* Set base UDP len, will be updated with payload and padding in Egress */
        hdr.udp.length = hdr.udp.minSizeInBytes() + hdr.ib_bth.minSizeInBytes() + 
                            hdr.ib_reth.minSizeInBytes() + 4 +
                             hdr.ue_flow_key.minSizeInBytes() + hdr.ue_flow_rule.minSizeInBytes(); 

        hdr.ib_bth.setValid();
        hdr.ib_bth.opcode = ib_opcode_t.RDMA_READ;
        hdr.ib_bth.se = 0;
        hdr.ib_bth.migration_req = 1;
        hdr.ib_bth.pad_count = 0;
        hdr.ib_bth.transport_version = 0;
        hdr.ib_bth.partition_key = 0xffff;
        hdr.ib_bth.reserved = 7;
        hdr.ib_bth.ack = 1;
        hdr.ib_bth.reserved2 = 0;

        hdr.ib_reth.setValid();
        hdr.ib_reth.remote_key = meta.mirror_truncate.rdma_remote_key;
        hdr.ib_reth.dma_len1 = 0;
        hdr.ib_reth.dma_len2 = hdr.ue_flow_key.minSizeInBytes() + hdr.ue_flow_rule.minSizeInBytes(); 
        hdr.ib_reth.addr = meta.mirror_truncate.payload_addr + PDR_TABLE_OFFSET; 
           
        hdr.ue_flow_key.setValid();
        hdr.ue_flow_key.ue_addr = hdr.ipv4.src_addr;
        hdr.ue_flow_key.inet_addr = hdr.ipv4.dst_addr;
        hdr.ue_flow_key.ue_port = hdr.udp.src_port;
        hdr.ue_flow_key.inet_port = hdr.udp.dst_port;
        hdr.ue_flow_rule.setValid();
        
        hdr.icrc.setValid(); 
        hdr.icrc2.setValid(); 
        

    }
}

#endif 
