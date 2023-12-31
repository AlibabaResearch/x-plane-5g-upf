#ifndef _INGRESS_PARSER_
#define _INGRESS_PARSER_

#include "../include/configuration.p4"
#include "../include/define_r.p4"

parser IngressParser(packet_in pkt, out headers_t hdr, out ig_metadata_t meta, out ingress_intrinsic_metadata_t ig_intr_md) {
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        meta.l4_lookup = {0, 0};
        transition select(ig_intr_md.ingress_port) {
            default: parse_ethernet;
        }
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ether_type_t.RDMA_INFO: parse_rdma_info;
            ether_type_t.IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_rdma_info {
        pkt.extract(hdr.rdma_info);
        transition select(hdr.rdma_info.code) {
            rdma_info_code_t.QP: parse_rdma_qp_info;
            rdma_info_code_t.MEM: parse_rdma_mem_info;
            rdma_info_code_t.ETH: parse_rdma_eth_info;
            default: accept;
        }
    }

    state parse_rdma_qp_info {
        pkt.extract(hdr.rdma_qp_info);
        transition accept;
    }

    state parse_rdma_mem_info {
        pkt.extract(hdr.rdma_mem_info);
        transition accept;
    }

    state parse_rdma_eth_info {
        pkt.extract(hdr.rdma_eth_info);
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            ipv4_protocol_t.TCP: parse_tcp;
            ipv4_protocol_t.UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        meta.l4_lookup = { hdr.tcp.src_port, hdr.tcp.dst_port };
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        meta.l4_lookup = { hdr.udp.src_port, hdr.udp.dst_port };
        transition select(hdr.udp.dst_port) {
            UDP_PORT_ROCEV2: parse_ib_bth;
            L4Port.GTP_GPDU: parse_gtpu;
            L4Port.IPV4_IN_UDP: parse_inner_ipv4;
            default: accept;
        }
    }

    // parse gtpu
    state parse_gtpu {
        pkt.extract(hdr.gtpu);
        transition select(hdr.gtpu.ex_flag, hdr.gtpu.seq_flag, hdr.gtpu.npdu_flag) {
            (0, 0, 0): parse_inner_ipv4;
            default: parse_gtpu_options;
        }
    }

    state parse_gtpu_options {
        pkt.extract(hdr.gtpu_options);
        bit<8> gtpu_ext_len = pkt.lookahead<bit<8>>();
        transition select(hdr.gtpu_options.next_ext, gtpu_ext_len) {
            (GTPU_NEXT_EXT_PSC, GTPU_EXT_PSC_LEN): parse_gtpu_ext_psc;
            (GTPU_NEXT_EXT_NONE, 8w0x0 &&& 8w0x00): parse_inner_ipv4;
            default: accept;
        }
    }

    state parse_gtpu_ext_psc {
        pkt.extract(hdr.gtpu_ext_psc);
        transition select(hdr.gtpu_ext_psc.next_ext) {
            GTPU_NEXT_EXT_NONE: parse_inner_ipv4;
            default: accept;
        }
    }

    state parse_inner_ipv4 {
        pkt.extract(hdr.inner_ipv4);
        transition select(hdr.inner_ipv4.protocol) {
            ipv4_protocol_t.UDP:  parse_inner_udp;
            ipv4_protocol_t.TCP:  parse_inner_tcp;
            ipv4_protocol_t.ICMP: parse_inner_icmp;
            default: accept;
        }
    }

    state parse_inner_udp {
        pkt.extract(hdr.inner_udp);
        transition accept;
    }

    state parse_inner_tcp {
        pkt.extract(hdr.inner_tcp);
        transition accept;
    }

    state parse_inner_icmp {
        pkt.extract(hdr.inner_icmp);
        transition accept;
    }

    // rdma packet

    state parse_ib_bth {
        pkt.extract(hdr.ib_bth);
        transition select(hdr.ib_bth.opcode) {
            ib_opcode_t.RDMA_ACK: parse_ib_aeth;
            ib_opcode_t.RDMA_READ_RESPONSE: parse_ib_aeth2;
            default: accept;
        }
    }

    state parse_ib_aeth {
        pkt.extract(hdr.ib_aeth);
        transition accept;
    }

    state parse_ib_aeth2 {
        pkt.extract(hdr.ib_aeth);
        transition parse_lookup_resp_type;
    }


    state parse_lookup_resp_type {
        pkt.extract(hdr.lookup_resp_type);
        transition select(hdr.lookup_resp_type.resp_type) {
            LookupRespType.UE: parse_resp_ue;
            LookupRespType.PDR: parse_resp_pdr_part0;
            LookupRespType.UE_FLOW: parse_resp_ue_flow;
            default: accept;
        }
    }

    state parse_resp_ue_flow {
        pkt.extract(hdr.ue_flow_key);
        pkt.extract(hdr.ue_flow_rule);
        pkt.extract(hdr.next_fetch_info);
        transition parse_packet_ue_key;
    }

    state parse_resp_ue {
        pkt.extract(hdr.ue_key);
        pkt.extract(hdr.ue);
        pkt.extract(hdr.next_fetch_info);
        transition parse_packet_ue_key;
    }

    state parse_resp_pdr_part0 {
        pkt.extract(hdr.ue_key);
        pkt.extract(hdr.pdr0);
        pkt.extract(hdr.pdr1);
        pkt.extract(hdr.pdr2);
        pkt.extract(hdr.pdr3);
        pkt.extract(hdr.pdr4);
        transition parse_resp_pdr_part1;
    }

    state parse_resp_pdr_part1 {
        pkt.extract(hdr.next_fetch_info);
        meta.current_qp_idx = hdr.next_fetch_info.current_qp_idx;
        meta.current_server_idx = hdr.next_fetch_info.current_server_idx;
        transition parse_packet_ue_key;
    }

    state parse_packet_ue_key {
        pkt.extract(hdr.packet_ue_key);
        transition parse_packet_pdr_key;
    }

    state parse_packet_pdr_key {
        pkt.extract(hdr.packet_pdr_key);
        transition accept;
    }

    state parse_payload_request {
        pkt.extract(hdr.payload_request);
        transition select(hdr.payload_request.padding) {
            1: parse_padding_1;
            2: parse_padding_2;
            3: parse_padding_3;
            default: accept;
        }
    }

    state parse_padding_1 {
        pkt.extract(hdr.padding_1);
        transition accept;
    }

    state parse_padding_2 {
        pkt.extract(hdr.padding_2);
        transition accept;
    }

    state parse_padding_3 {
        pkt.extract(hdr.padding_3);
        transition accept;
    }
}

control IngressDeparser(packet_out pkt, inout headers_t hdr, in ig_metadata_t meta,
                        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    Mirror() mirror;

    apply {
        if (ig_dprsr_md.mirror_type == TRUNCATE_MIRROR_TYPE) {
            mirror.emit<mirror_truncate_h>(meta.mirror_session, {
                meta.packet_type,
                meta.payload_addr,
                meta.write_index,
                meta.read_index,
                meta.payload_len, //meta.hdr_idx,
                meta.server_qp_index,
                meta.server_index,
                meta.server_mac_addr_1,
                meta.server_mac_addr_2,
                //meta.server_ip_addr,
                meta.rdma_remote_key,
                meta.pdr_fetch_round_id
            });
        } 
        else if (ig_dprsr_md.mirror_type == WRITE_MIRROR_TYPE) {
            mirror.emit<mirror_truncate_h>(meta.mirror_session, {
                meta.packet_type,
                meta.payload_addr,
                meta.write_index,
                meta.read_index,
                meta.payload_len, //meta.hdr_idx,
                meta.server_qp_index,
                meta.server_index,
                meta.server_mac_addr_1,
                meta.server_mac_addr_2,
                //meta.server_ip_addr,
                meta.rdma_remote_key,
                meta.pdr_fetch_round_id
            });
        }

        pkt.emit(hdr);
    }
}

#endif /* _INGRESS_PARSER_ */
