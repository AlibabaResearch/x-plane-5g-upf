#ifndef _FETCH_RULE_
#define _FETCH_RULE_

#include "../include/types_r.p4"
#include "../include/configuration.p4"
#include "../include/registers.p4"

// initialize the first round of rule fetch
control FetchRule(inout headers_t hdr, inout ig_metadata_t meta,
                     //inout ingress_intrinsic_metadata_t ig_intr_md,
                     in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                     inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                     inout ingress_intrinsic_metadata_for_tm_t ig_tm_md,
                     in bit<16> server_mac_addr_1,
                     in bit<32> server_mac_addr_2,
                     in ipv4_addr_t server_ip_addr,
                     in bit<32> mem_addr_offset,
                     in bit<16> current_server_idx,
                     in bit<16> current_qp_idx,
                     in bit<32> addr_1,
                     in bit<32> addr_2,
                     in bit<32> rdma_remote_key) {
                        
    bit<16> payload_len;
    bit<64> base_addr_ue;
    bit<64> final_offset = 32w0x0 ++ mem_addr_offset;

    action add_addr_act() {
        base_addr_ue = addr_1 ++ addr_2;
    }

    table add_addr_tbl {
		key = {}
		actions = {add_addr_act;}
		size = 1;
		default_action = add_addr_act;
	}

    /* RDMA WRITE Action */
    action send_rdma_write() {
        /* Chosen RDMA Server MAC Address */
        hdr.ethernet.dst_addr_1 = server_mac_addr_1;
        hdr.ethernet.dst_addr_2 = server_mac_addr_2;
        /* Fake MAC Address as source */
        hdr.ethernet.src_addr = 0x000000000001;

        /* to be modified */
        hdr.packet_ue_key.setValid();
        hdr.packet_ue_key.teid = hdr.gtpu.pdr_round;
        hdr.packet_ue_key.src_addr = hdr.inner_ipv4.src_addr;
        hdr.packet_ue_key.qfi = hdr.gtpu_ext_psc.qfi;
        hdr.packet_pdr_key.setValid(); 
        hdr.packet_pdr_key.qfi = hdr.gtpu_ext_psc.qfi;
        hdr.packet_pdr_key.ue_port = hdr.udp.src_port;
        hdr.packet_pdr_key.inet_port = hdr.inner_udp.dst_port;
        hdr.packet_pdr_key.ue_addr = hdr.ipv4.src_addr;
        hdr.packet_pdr_key.inet_addr = hdr.ipv4.dst_addr;

        /* Static RDMA Client IP Address where the connection is opened */
        hdr.ipv4.src_addr = RDMA_IP;//RDMA_IP;
        /* Chosen RDMA Server IP Address */
        hdr.ipv4.dst_addr = server_ip_addr; 
		hdr.ipv4.ttl = 64;
        hdr.ipv4.flags = 0x2;
        hdr.ipv4.protocol = ipv4_protocol_t.UDP;
        /* Set base IPv4 len, will be updated with payload and padding in Egress */
        hdr.ipv4.total_len = hdr.ipv4.minSizeInBytes() + hdr.udp.minSizeInBytes() + 
                        hdr.ib_bth.minSizeInBytes() + hdr.ib_reth.minSizeInBytes() + 4; 

        hdr.udp.setValid();
        hdr.udp.src_port = 0;
        hdr.udp.dst_port = UDP_PORT_ROCEV2;
        hdr.udp.checksum = 0;

        /* Set base UDP len, will be updated with payload and padding in Egress */
        hdr.udp.length = hdr.udp.minSizeInBytes() + hdr.ib_bth.minSizeInBytes() + 
                            hdr.ib_reth.minSizeInBytes() + 4;

        hdr.ib_bth.setValid();
        hdr.ib_bth.opcode = ib_opcode_t.RDMA_WRITE; 
        hdr.ib_bth.se = 0;
        hdr.ib_bth.migration_req = 1;
        hdr.ib_bth.pad_count = 0;
        hdr.ib_bth.transport_version = 0;
        hdr.ib_bth.partition_key = 0xffff;
        hdr.ib_bth.reserved = 1; // 1: write ue_flow_table; 2: write ue_table 3: write pdr table
        hdr.ib_bth.ack = 1;
        hdr.ib_bth.reserved2 = 0;
        hdr.ib_bth.dst_qp = (bit<24>) (current_server_idx << QP_POWER); //determined in the egress logic
        /* Store the QP Index where we will read the real seq_n in the Egress */
        hdr.ib_bth.psn = (bit<24>) current_qp_idx;

        hdr.ib_reth.setValid();
        hdr.ib_reth.addr = base_addr_ue + final_offset; // lyz
        hdr.ib_reth.remote_key = rdma_remote_key;
        hdr.ib_reth.dma_len1 = 0;
        hdr.ib_reth.dma_len2 = payload_len; 

        hdr.payload_request.setInvalid();

        hdr.next_fetch_info.setValid();
        hdr.next_fetch_info.addr = base_addr_ue;
        hdr.next_fetch_info.pdr_fetch_round_id = 0;
        hdr.next_fetch_info.current_server_idx = 0;
        hdr.next_fetch_info.current_qp_idx = current_qp_idx;
        hdr.next_fetch_info.payload_len = payload_len;
        hdr.next_fetch_info.mem_offset = UE_TABLE_OFFSET; //UE_FLOW_TABLE_OFFSET;
        hdr.next_fetch_info.rdma_remote_key = rdma_remote_key;

		hdr.icrc.setValid(); 
    }

    /* Packet Cloning action - to construct RDMA read */
    action mirror() {
        meta.payload_addr = base_addr_ue + final_offset;
        meta.payload_len = payload_len;
        meta.server_qp_index = current_qp_idx + (bit<16>) hdr.ib_bth.dst_qp;
        meta.server_index = current_server_idx << QP_POWER; 
        meta.server_mac_addr_1 = server_mac_addr_1;
        meta.server_mac_addr_2 = server_mac_addr_2;
        meta.server_ip_addr = server_ip_addr;
        meta.rdma_remote_key = rdma_remote_key;
        meta.pdr_fetch_round_id = 0;

        ig_dprsr_md.mirror_type = TRUNCATE_MIRROR_TYPE;
        meta.packet_type = PKT_TYPE_MIRROR_TRUNCATE;
    }


    apply {
        /* Compute payload len. Should be done in another action to avoid multiple-stages */
        payload_len = hdr.ipv4.total_len - hdr.ipv4.minSizeInBytes() - hdr.udp.minSizeInBytes() +
                        hdr.next_fetch_info.minSizeInBytes() + hdr.packet_ue_key.minSizeInBytes() + hdr.packet_pdr_key.minSizeInBytes();
        base_addr_ue = addr_1 ++ addr_2;
        send_rdma_write();
        mirror();
    }
}


control KeepFetchRule0(inout headers_t hdr, inout ig_metadata_t meta, 
                     in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                     inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                     in bit<16> server_mac_addr_1,
                     in bit<32> server_mac_addr_2, 
                     in ipv4_addr_t server_ip_addr) {
    bit<16> qp_idx;

    apply {
        qp_idx = hdr.next_fetch_info.current_server_idx;
        hdr.ethernet.dst_addr_1 = server_mac_addr_1;
        hdr.ethernet.dst_addr_2 = server_mac_addr_2;
        hdr.ethernet.src_addr = 0x000000000001;
        hdr.ipv4.src_addr = RDMA_IP;
        hdr.ipv4.dst_addr = server_ip_addr; 
        hdr.ipv4.ttl = 64;
        hdr.ipv4.flags = 0x2;
        hdr.ipv4.protocol = ipv4_protocol_t.UDP;
        hdr.ipv4.total_len = hdr.ipv4.total_len; 

        hdr.udp.setValid();
        hdr.udp.src_port = 0;
        hdr.udp.dst_port = UDP_PORT_ROCEV2;
        hdr.udp.checksum = 0;
        hdr.udp.length = hdr.udp.length; // compilation fails with this

        hdr.ib_bth.setValid();
        hdr.ib_bth.opcode = ib_opcode_t.RDMA_WRITE; 
        hdr.ib_bth.se = 0;
        hdr.ib_bth.migration_req = 1;
        hdr.ib_bth.pad_count = 0;
        hdr.ib_bth.transport_version = 0;
        hdr.ib_bth.partition_key = 0xffff;
        hdr.ib_bth.reserved = 9;
        hdr.ib_bth.ack = 1;
        hdr.ib_bth.reserved2 = 0;
        hdr.ib_bth.psn = (bit<24>) qp_idx; 
        hdr.ib_reth.setValid();
        hdr.ib_reth.remote_key = 0;
        hdr.ib_reth.dma_len1 = 0;
        hdr.ib_reth.dma_len2 = hdr.udp.length - 28 - UE_FLOW_KEY_LEN - UE_FLOW_RULE_LEN - 3;

        hdr.next_fetch_info.pdr_fetch_round_id = hdr.next_fetch_info.pdr_fetch_round_id + 1;

        // mirror
        meta.payload_len = hdr.udp.length - 28 - UE_FLOW_KEY_LEN - UE_FLOW_RULE_LEN - 3;
        meta.server_qp_index = (bit<16>) hdr.ib_bth.dst_qp + qp_idx; 
        meta.server_index = 0;
        meta.server_mac_addr_1 = server_mac_addr_1;
        meta.server_mac_addr_2 = server_mac_addr_2;
        meta.server_ip_addr = server_ip_addr;
        meta.rdma_remote_key = hdr.next_fetch_info.rdma_remote_key;
        meta.pdr_fetch_round_id = 3; // only used to signal the flow control

        ig_dprsr_md.mirror_type = TRUNCATE_MIRROR_TYPE;
        meta.packet_type = PKT_TYPE_MIRROR_TRUNCATE;
        
        hdr.ib_aeth.setInvalid();
        hdr.ue_key.setInvalid();
        hdr.ue_flow_key.setInvalid();
        hdr.ue_flow_rule.setInvalid();
        hdr.lookup_resp_type.setInvalid();
        hdr.pdr0.setInvalid();
        hdr.pdr1.setInvalid();
        hdr.pdr2.setInvalid();
        hdr.pdr3.setInvalid();
        hdr.pdr4.setInvalid();
        hdr.ue.setInvalid();
    }
}

control KeepFetchRule1(inout headers_t hdr, inout ig_metadata_t meta, 
                     in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                     inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                     in bit<16> server_mac_addr_1,
                     in bit<32> server_mac_addr_2,   
                     in ipv4_addr_t server_ip_addr) {
    bit<16> qp_idx;

    apply {
        qp_idx = hdr.next_fetch_info.current_server_idx;
        hdr.ethernet.dst_addr_1 = server_mac_addr_1;
        hdr.ethernet.dst_addr_2 = server_mac_addr_2;
        hdr.ethernet.src_addr = 0x000000000001;
        hdr.ipv4.src_addr = RDMA_IP;
        hdr.ipv4.dst_addr = server_ip_addr; 
        hdr.ipv4.ttl = 64;
        hdr.ipv4.flags = 0x2;
        hdr.ipv4.protocol = ipv4_protocol_t.UDP;
        hdr.ipv4.total_len = hdr.ipv4.total_len; // compilation fails with this

        hdr.udp.src_port = 0;
        hdr.udp.dst_port = UDP_PORT_ROCEV2;
        hdr.udp.checksum = 0;
        hdr.udp.length = hdr.udp.length; // compilation fails with this

        hdr.ib_bth.opcode = ib_opcode_t.RDMA_WRITE; 
        hdr.ib_bth.se = 0;
        hdr.ib_bth.migration_req = 1;
        hdr.ib_bth.pad_count = 0;
        hdr.ib_bth.transport_version = 0;
        hdr.ib_bth.partition_key = 0xffff;
        hdr.ib_bth.reserved = 9;
        hdr.ib_bth.ack = 1;
        hdr.ib_bth.reserved2 = 0;
        hdr.ib_bth.psn = (bit<24>) qp_idx;
        
        hdr.ib_reth.setValid();
        hdr.ib_reth.remote_key = 0;
        hdr.ib_reth.dma_len1 = 0;
        hdr.ib_reth.dma_len2 = hdr.udp.length - 28 - UE_KEY_LEN - UE_RULE_LEN;
        hdr.next_fetch_info.pdr_fetch_round_id = hdr.next_fetch_info.pdr_fetch_round_id + 1;

        // mirror
        meta.payload_len = hdr.udp.length - 28 - UE_KEY_LEN - UE_RULE_LEN;
        meta.server_qp_index = (bit<16>) hdr.ib_bth.dst_qp + qp_idx; 
        meta.server_index = 0;
        meta.server_mac_addr_1 = server_mac_addr_1;
        meta.server_mac_addr_2 = server_mac_addr_2;
        meta.server_ip_addr = server_ip_addr;
        meta.rdma_remote_key = hdr.next_fetch_info.rdma_remote_key;
        meta.pdr_fetch_round_id = 3; // only used to signal the flow control

        ig_dprsr_md.mirror_type = TRUNCATE_MIRROR_TYPE;
        meta.packet_type = PKT_TYPE_MIRROR_TRUNCATE;
        
        hdr.ib_aeth.setInvalid();
        hdr.ue_key.setInvalid();
        hdr.ue_flow_key.setInvalid();
        hdr.ue_flow_rule.setInvalid();
        hdr.lookup_resp_type.setInvalid();
        hdr.pdr0.setInvalid();
        hdr.pdr1.setInvalid();
        hdr.pdr2.setInvalid();
        hdr.pdr3.setInvalid();
        hdr.pdr4.setInvalid();
        hdr.ue.setInvalid();
    }
}

control WriteFlowTable(inout headers_t hdr, inout ig_metadata_t meta,  
                     inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                     in bit<16> server_mac_addr_1,
                     in bit<32> server_mac_addr_2,
                     in ipv4_addr_t server_ip_addr) {
    bit<16> qp_idx;

    apply{
        qp_idx = hdr.next_fetch_info.current_server_idx;

        // original packets: rdma read response
        // mirrored packet as the original packet
        // using reserved field to identify at egress
        meta.payload_addr = hdr.next_fetch_info.addr; 
        meta.server_qp_index =  (bit<16>) hdr.ib_bth.dst_qp + qp_idx;
        meta.server_index = 0;
        meta.server_mac_addr_1 = server_mac_addr_1;
        meta.server_mac_addr_2 = server_mac_addr_2;
        meta.server_ip_addr = server_ip_addr;
        meta.rdma_remote_key = hdr.next_fetch_info.rdma_remote_key;
        meta.pdr_fetch_round_id = 2; 
        ig_dprsr_md.mirror_type = WRITE_MIRROR_TYPE;
        meta.packet_type = PKT_TYPE_MIRROR_TRUNCATE;
    }
}

control ReadUeState(inout headers_t hdr, inout ig_metadata_t meta,  
                     inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                     in bit<16> server_mac_addr_1,
                     in bit<32> server_mac_addr_2,
                     in ipv4_addr_t server_ip_addr) {
    bit<16> qp_idx;

    apply{
        qp_idx = hdr.next_fetch_info.current_server_idx;
        meta.server_qp_index =  (bit<16>) hdr.ib_bth.dst_qp + qp_idx;
        meta.server_index = 0; 
        meta.server_mac_addr_1 = server_mac_addr_1;
        meta.server_mac_addr_2 = server_mac_addr_2;
        meta.server_ip_addr = server_ip_addr;
        meta.rdma_remote_key = hdr.next_fetch_info.rdma_remote_key;
        meta.pdr_fetch_round_id = 1; 
        ig_dprsr_md.mirror_type = WRITE_MIRROR_TYPE;
        meta.packet_type = PKT_TYPE_MIRROR_TRUNCATE;
    }
}


control WriteFlowState(inout headers_t hdr, inout ig_metadata_t meta,  
                     inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                     in bit<16> server_mac_addr_1,
                     in bit<32> server_mac_addr_2,
                     in ipv4_addr_t server_ip_addr) {
    bit<16> qp_idx;

    apply{
        qp_idx = hdr.next_fetch_info.current_server_idx;

        // original packets: rdma read response
        // mirrored packet as the original packet
        // using reserved field to identify at egress
        meta.payload_addr = hdr.next_fetch_info.addr; 
        meta.server_qp_index =  (bit<16>) hdr.ib_bth.dst_qp + qp_idx;
        meta.server_index = 0; 
        meta.server_mac_addr_1 = server_mac_addr_1;
        meta.server_mac_addr_2 = server_mac_addr_2;
        meta.server_ip_addr = server_ip_addr;
        meta.rdma_remote_key = hdr.next_fetch_info.rdma_remote_key;
        meta.pdr_fetch_round_id = 4; 
        ig_dprsr_md.mirror_type = WRITE_MIRROR_TYPE;
        meta.packet_type = PKT_TYPE_MIRROR_TRUNCATE;
    }
}


#endif 
