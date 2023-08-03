#ifndef _HEADERS_
#define _HEADERS_

#include "types_r.p4"
#include "define_r.p4"
#include "configuration.p4"
//#include "types.p4"

/* Chunked header */
/* This is sized to contain UDP */
// @pa_no_overlay("ingress", "hdr.hdr_chunks.blk_0")
// @pa_no_overlay("ingress", "hdr.hdr_chunks.blk_1")
// @pa_no_overlay("ingress", "hdr.hdr_chunks.blk_2")
// @pa_no_overlay("ingress", "hdr.hdr_chunks.blk_3")
// @pa_no_overlay("ingress", "hdr.hdr_chunks.blk_4")
// @pa_no_overlay("ingress", "hdr.hdr_chunks.blk_5")
// @pa_no_overlay("ingress", "hdr.hdr_chunks.blk_6")
// @pa_no_overlay("ingress", "hdr.hdr_chunks.blk_7")
// @pa_no_overlay("ingress", "hdr.hdr_chunks.blk_8")
// @pa_no_overlay("ingress", "hdr.hdr_chunks.blk_9")
// @pa_no_overlay("ingress", "hdr.hdr_chunks.blk_10")
header hdr_chunk_h {
    bit<32> blk_0;
    bit<32> blk_1;
    bit<32> blk_2;
    bit<32> blk_3;
    bit<32> blk_4;
    bit<32> blk_5;
    bit<32> blk_6;
    bit<32> blk_7;
    bit<32> blk_8;
    bit<32> blk_9;
    bit<16> blk_10;
}

// @pa_no_overlay("ingress", "hdr.hdr_chunks_tcp.blk_11")
// @pa_no_overlay("ingress", "hdr.hdr_chunks_tcp.blk_12")
// @pa_no_overlay("ingress", "hdr.hdr_chunks_tcp.blk_13")
// @pa_no_overlay("ingress", "hdr.hdr_chunks_tcp.blk_14")
header hdr_chunk_tcp_h {
    bit<16> blk_11;
    bit<32> blk_12;
    bit<32> blk_13;
    bit<16> blk_14;
}

/* Mirroring */
//rdma stack info
header mirror_truncate_h {
    pkt_type_t pkt_type;
    bit<64> payload_addr;
    /*paging*/
    bit<8> write_index;
    bit<8> read_index;
    bit<16> payload_len;
    //bit<16> hdr_idx;
    bit<16> server_qp_index;
    bit<16> server_index;
    bit<16> server_mac_addr_1;
    bit<32> server_mac_addr_2;
    bit<32> server_ip_addr;
    bit<32> rdma_remote_key;
    bit<8> pdr_fetch_round_id;
}

//eth info
header mirror_qp_restore_h {
    pkt_type_t pkt_type;
    bit<16> server_mac_addr_1;
    bit<32> server_mac_addr_2;
    bit<16> qp_index;
}

/* RDMA Info Header */
header rdma_info_h {
    rdma_info_code_t code;
}

header rdma_qp_info_h {
    bit<16> enable_timer;
    bit<16> index;
    bit<32> dst_qp;
}

header rdma_mem_info_h {
    bit<16> server_id;
    bit<32> remote_address1;
    bit<32> remote_address2;
    bit<32> remote_key;
}

header rdma_eth_info_h {
    bit<16> server_id;
    @padding bit<16> unused_bits;
    bit<16> mac_address1;
    bit<32> mac_address2;
    bit<32> ip_address;
}

/* QP Restore Header */
header qp_restore_h {
    bit<16> index;
}

/* Standard headers */
header ethernet_h_r {
    bit<16> dst_addr_1;
    bit<32> dst_addr_2;
    mac_addr_t src_addr;
    ether_type_t ether_type;
}

header ipv4_h_r {
    bit<4> version;
    bit<4> ihl;
    bit<6> dscp;
    bit<2> ecn;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    ipv4_protocol_t protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header tcp_h_r {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_n;
    bit<32> ack_n;
    bit<4> data_offset;
    bit<4> res;
    bit<1> cwr;
    bit<1> ece;
    bit<1> urg;
    bit<1> ack;
    bit<1> psh;
    bit<1> rst;
    bit<1> syn;
    bit<1> fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h_r {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> length;
    bit<16> checksum;
}

/* InfiniBand-RoCE Base Transport Header */
header ib_bth_h {
    ib_opcode_t opcode;
    bit<1> se;
    bit<1> migration_req;
    bit<2> pad_count;
    bit<4> transport_version;
    bit<16> partition_key;
    bit<8> reserved;
    bit<24> dst_qp;
    bit<1> ack;
    bit<7> reserved2;
    bit<24> psn;
}

/* InfiniBand-RoCE RDMA Extended Transport Header */
header ib_reth_h {
    bit<64> addr;
    bit<32> remote_key;
    bit<16> dma_len1;
    bit<16> dma_len2;
}

/* InfiniBand-RoCE ACK Extended Transport Header */
header ib_aeth_h {
    bit<1> reserved;
    bit<2> opcode;
    bit<5> error_code;
    bit<24> msn;
}

/* Infiniband-RoCE Paddings */
header ib_padding_1_h {
    bit<8> padding;
}

header ib_padding_2_h {
    bit<16> padding;
}

header ib_padding_3_h {
    bit<24> padding;
}

/* Custom Payload-Splitter Info Header */
@pa_no_overlay("egress", "hdr.payload_splitter.marker")
@pa_no_overlay("egress", "hdr.payload_splitter.payload_address")
@pa_no_overlay("egress", "hdr.payload_splitter.payload_len")
@pa_no_overlay("egress", "hdr.payload_splitter.server_qp_index")
@pa_no_overlay("egress", "hdr.payload_splitter.server_index")
header payload_splitter_h {
    bit<32> marker;
    bit<64> payload_address;
    bit<16> payload_len;
    bit<16> server_qp_index;
    bit<16> server_index;
}

/* Custom Payload-Request Header */
/*padding*/
header payload_request_h {
    bit<8> padding;
    bit<8> padding1;
    bit<8> padding2;
    bit<8> hdr_idx;
}

/* Bridge Ingress->Egress Headers */
@flexible
header bridge_payload_h {
    bit<16> server_mac_addr_1;
    bit<32> server_mac_addr_2;
    ipv4_addr_t server_ip_addr;
    bit<32> r_key;
}

/* HEADERS */
header icrc_h {
	bit<32> icrc;
}

header udp_payload_h { // 18 bytes for RDMA stack test
	bit<32> p1;
	bit<32> p2;
	bit<32> p3;
	bit<32> p4;
	bit<16> p5;
}


/* meta data definitions copied from sna upf */
//not sure what this is for
struct hash_metadata_t{
    bit<32>  flowId;
}

// Data associated with a PDR entry
struct pdr_metadata_t {
    pdr_id_t id;
    counter_index_t ctr_idx;
    bit<6> tunnel_out_qfi;
}

// Data associated with Buffering and BARs
struct bar_metadata_t {
    bool needs_buffering;
    bar_id_t bar_id;
    bit<32> ddn_delay_ms; // unused so far
    bit<32> suggest_pkt_count; // unused so far
}

// Data associated with a FAR entry. Loaded by a FAR (except ID which is loaded by a PDR)
struct far_metadata_t {
    far_id_t    id;

    // Buffering, dropping, tunneling etc. are not mutually exclusive.
    // Hence, they should be flags and not different action types.
    bool needs_dropping;
    bool needs_tunneling;
    bool notify_cp;

    TunnelType  tunnel_out_type;
    ipv4_addr_t tunnel_out_src_ipv4_addr;
    ipv4_addr_t tunnel_out_dst_ipv4_addr;
    L4Port      tunnel_out_udp_sport;
    teid_t      tunnel_out_teid;

    ipv4_addr_t next_hop_ip;
}

header icmp_h_r {
    bit<8> icmp_type;
    bit<8> icmp_code;
    bit<16> checksum;
    bit<16> identifier;
    bit<16> sequence_number;
    bit<64> timestamp;
}

header gtpu_t { // 8 bytes
    bit<3>          version;    /* version */
    bit<1>          pt;         /* protocol type */
    bit<1>          spare;      /* reserved */
    bit<1>          ex_flag;    /* next extension hdr present? */
    bit<1>          seq_flag;   /* sequence no. */
    bit<1>          npdu_flag;  /* n-pdn number present ? */
    GTPUMessageType msgtype;    /* message type, 8bit */
    bit<16>         msglen;     /* message length */
    //teid_t          teid;       /* tunnel endpoint id */ //bit<32> divided for test
    bit<8>          reserved1;
    bit<8>          reserved2;
    bit<8>          is_first_pkt;
    bit<8>          pdr_round;
}

// Follows gtpu_t if any of ex_flag, seq_flag, or npdu_flag is 1.
header gtpu_options_t { // 4 bytes
    bit<16> seq_num;   /* Sequence number */
    bit<8>  n_pdu_num; /* N-PDU number */
    bit<8>  next_ext;  /* Next extension header */
}

// GTPU extension: PDU Session Container (PSC) -- 3GPP TS 38.415 version 15.2.0
// https://www.etsi.org/deliver/etsi_ts/138400_138499/138415/15.02.00_60/ts_138415v150200p.pdf
header gtpu_ext_psc_t { // 4 bytes
    bit<8> len;      /* Length in 4-octet units (common to all extensions) */
    bit<4> type;     /* Uplink or downlink */
    bit<4> spare0;   /* Reserved */
    bit<1> ppp;      /* Paging Policy Presence (UL only, not supported) */
    bit<1> rqi;      /* Reflective QoS Indicator (UL only) */
    bit<6> qfi;      /* QoS Flow Identifier */
    bit<8> next_ext;
}

header pdr_h { // 18 bytes * 5 => changed to 4 = 72
    // PDRs
    // InterfaceType src_iface; //8 bits
    // ipv4_addr_t dst_addr; // 32 bits
    //bit<32> teid;
    ipv4_addr_t ue_addr; // 32 bits
    ipv4_addr_t inet_addr; //32 bits
    bit<16> ue_port;
    bit<16> inet_port; 
    IpProtocol proto; //8 bits
    bit<6> qfi;  // used as padding
    // FAR
    bool needs_dropping; // 1 bit
    //ipv4_addr_t next_hop_ip; // 32 bits
    // BAR
    bool needs_buffering;  
    // URR
    bit<32> counter;
}

header ue_key_h { //9 bytes
    //bit<32> teid;
    bit<8> teid;
    bit<8> teid0;
    bit<8> teid1;
    bit<8> teid2;
    ipv4_addr_t src_addr; //32 bits
    bit<6> qfi;
    bit<2> padding;
}

header ue_h { // 90 bytes  todo: keep consistent with PDR length or change the RDMA read length
    bit<32> counter; 
    bool pdr_exits;
    /*paging*/
    bool idle_locker;
    bit<6> padding;
    bit<8> write_index;
    bit<8> read_index;
    bit<8> idle;
    bit<16> reserved;
    bit<640> padding0;
}

header ue_flow_key_h {  // 13 bytes
    ipv4_addr_t ue_addr; // 32 bits
    ipv4_addr_t inet_addr; //32 bits
    bit<16> ue_port;
    bit<16> inet_port; 
    IpProtocol proto; //8 bits
}

header ue_flow_rule_h { // 5 bytes // keep consistent with PDR
    bool needs_dropping; // 1 bit
    // BAR
    bool needs_buffering;  
    // URR
    bit<32> counter; // state data needs to be organized in a continuous space
    bit<22> padding; // pad to 7 bytes [for ue flow write]
}

header pdr_next_fetch_info_h {
    bit<64> addr;
    bit<16> current_server_idx;
    bit<16> current_qp_idx;
    bit<8> pdr_fetch_round_id;
    bit<16> payload_len;
    bit<32> mem_offset;
    bit<32> rdma_remote_key;
    bit<16> ints_fwd; // timestamp for latency test
    bit<16> ets_fwd;
    bit<16> st_lk; // timestamp for latency test
    /*paging*/
    //bit<16> ed_lk;
    bit<8> ed_lk;
    bit<8> has_value;
    //bit<16> ets_fwd2;
    //bit<48> ints_rdma;
    //bit<48> ets_rdma;
    //bit<CONCURRENCY_CONTROL_TABLE_SIZE_POWER> c_slot_idx;
    bit<64> mem_offset2;
}

header lookup_resp_h {
    LookupRespType resp_type;
}

struct headers_t {
    hdr_chunk_h hdr_chunks;
    hdr_chunk_tcp_h hdr_chunks_tcp;

    ethernet_h_r ethernet;

    rdma_info_h rdma_info;
    rdma_qp_info_h rdma_qp_info;
    rdma_mem_info_h rdma_mem_info;
    rdma_eth_info_h rdma_eth_info;
    qp_restore_h qp_restore;

    /* (parser modification required) */
    //fabric_h fabric;
    //cpu_h cpu;
    //vlan_tag_t vlan_tag;
    
    ipv4_h_r ipv4;
    udp_h_r udp;
    tcp_h_r tcp;

    /* rdma info */
    payload_splitter_h payload_splitter;
    bridge_payload_h bridge_payload;
    ib_bth_h ib_bth;
    ib_reth_h ib_reth;
    ib_aeth_h ib_aeth;
    payload_request_h payload_request;
    ib_padding_1_h padding_1;
    ib_padding_2_h padding_2;
    ib_padding_3_h padding_3;
    
    /* lookup design */
    lookup_resp_h lookup_resp_type; 
    ue_key_h ue_key;
    ue_flow_key_h ue_flow_key;
    // [rules]
    ue_flow_rule_h ue_flow_rule;
    // number of pdr equals NUM_PDR_PER_FETCH
    pdr_h pdr0;
    pdr_h pdr1;
    pdr_h pdr2;
    pdr_h pdr3;
    pdr_h pdr4;
    // pdr_h pdr5;
    // pdr_h pdr6;
    // pdr_h pdr7;
    // pdr_h pdr8;
    // pdr_h pdr9;
    ue_h ue;
    pdr_next_fetch_info_h next_fetch_info;
    ue_key_h packet_ue_key;
    pdr_h packet_pdr_key;
    //ib_padding_2_h pdr_padding;
    
    icrc_h icrc;
    icrc_h icrc2;

    /* udp payload - encaped gtp - (parser modification required) */
    gtpu_t gtpu;
    gtpu_options_t gtpu_options;
    gtpu_ext_psc_t gtpu_ext_psc;
    ipv4_h_r outer_ipv4;
    udp_h_r outer_udp;
    tcp_h_r outer_tcp;
    icmp_h_r outer_icmp;
    ipv4_h_r inner_ipv4;
    udp_h_r inner_udp;
    tcp_h_r inner_tcp;
    icmp_h_r inner_icmp;

}



/* INGRESS METADATA */
struct ig_metadata_t {
    l4_lookup_t l4_lookup; 
    // bit<8> to_split;
    // bit<8> is_split;
    /*paging*/
    bit<8>  write_index;
    bit<8> read_index;
    MirrorId_t mirror_session;
    pkt_type_t packet_type;
    bit<16> server_mac_addr_1;
    bit<32> server_mac_addr_2;
    bit<64> payload_addr;
    bit<16> payload_len;
    bit<16> hdr_idx;
    bit<16> server_qp_index;
    bit<16> restore_qp_index;
    bit<16> server_index;
    bit<16> current_server_idx;
    bit<16> current_qp_idx;
    bit<32> server_ip_addr;
    bit<32> rdma_remote_key;
    bit<8> pdr_fetch_round_id;

    /* meta info copied from sna upf */
    Direction direction;

    // SEID and F-TEID currently have no use in fast path
    teid_t teid;    // local Tunnel ID.  F-TEID = TEID + GTP endpoint address
    // seid_t seid; // local Session ID. F-SEID = SEID + GTP endpoint address

    // fteid_t fteid;
    fseid_t fseid;

    ipv4_addr_t next_hop_ip;

    bit<1> mirror_hit;
    bool needs_gtpu_decap;
    bool needs_udp_decap; // unused
    bool needs_vlan_removal; // unused
    bool needs_ext_psc; // used to signal gtpu encap with PSC extension

    InterfaceType src_iface;
    InterfaceType dst_iface; // unused

    ipv4_addr_t ue_addr;
    ipv4_addr_t inet_addr;
    L4Port ue_l4_port;
    L4Port inet_l4_port;

    L4Port l4_sport;
    L4Port l4_dport;
    IpProtocol l4_proto;

    net_instance_t net_instance;

    pdr_metadata_t pdr;
    far_metadata_t far;
    bar_metadata_t bar;

    L4Port inner_l4_sport;
    L4Port inner_l4_dport;
    IpProtocol inner_l4_proto;

    bit<8> err_code;
    hash_metadata_t hash_meta; //hash meta
    bit<32> ul_counter;
}

/* EGRESS METADATA */
struct eg_metadata_t {
    mirror_truncate_h mirror_truncate;
    mirror_qp_restore_h mirror_qp_restore;
}

#endif /* _HEADERS_ */
