#ifndef __DEFINE__
#define __DEFINE__



typedef bit<32> far_info_id_t;
typedef bit<32> pdr_id_t;
typedef bit<32> far_id_t;
typedef bit<32> qer_id_t;
typedef bit<32> bar_id_t;
typedef bit<32> qfi_t;
typedef bit<32> net_instance_t;
typedef bit<32> counter_index_t;
typedef bit<32>  scheduling_priority_t;

typedef bit<32> teid_t;
typedef bit<64> seid_t;
// F-TEID = (4-byte)TEID + GTP endpoint (gnodeb OR UPF) address
typedef bit<64> fteid_t;
// F-SEID = 8-byte SEID + UPF IP(v4/v6) address
typedef bit<96> fseid_t;
// In hardware the full F-TEID and F-SEIDs should be replaced by shorter
// unique identifiers to reduce memory. The slow path can maintain the
// short ID <--> F-TEID/F-SEID mapping.

// todo: to make clear what each field means
const bit<16> UDP_PORT_GTPU = 2152;
const bit<3> GTP_V1 = 0x1;
const bit<1> GTP_PROTOCOL_TYPE_GTP = 0x1;
const bit<8> GTP_MESSAGE_TYPE_UPDU = 0xff;
const bit<8> GTPU_NEXT_EXT_NONE = 0x0;
const bit<8> GTPU_NEXT_EXT_PSC = 0x85;
const bit<4> GTPU_EXT_PSC_TYPE_DL = 4w0; // Downlink
const bit<4> GTPU_EXT_PSC_TYPE_UL = 4w1; // Uplink
const bit<8> GTPU_EXT_PSC_LEN = 8w1; // 1*4-octets


enum bit<8> InterfaceType {
    UNKNOWN       = 0x0,
    ACCESS        = 0x1,
    CORE          = 0x2,
    N6_LAN        = 0x3, // unused
    VN_INTERNAL   = 0x4, // unused
    CONTROL_PLANE = 0x5 // N4 and N4-u
}

enum bit<16> L4Port {
    DHCP_SERV       = 67, // naming this DHCP_SERVER causes a syntax error..
    DHCP_CLIENT     = 68,
    GTP_GPDU        = 2152,
    IPV4_IN_UDP     = 9875 // placeholder. port has not yet been assigned by IANA
}

enum bit<8> IpProtocol {
    ICMP    = 1,
    TCP     = 6,
    UDP     = 17
}

enum bit<8> Direction {
    UNKNOWN             = 0x0,
    UPLINK              = 0x1,
    DOWNLINK            = 0x2,
    OTHER               = 0x3
};

enum bit<8> TunnelType {
    UNKNOWN = 0x0,
    IP      = 0x1, // unused
    UDP     = 0x2, // unused
    GTPU    = 0x3
}

enum bit<8> GTPUMessageType {
    GPDU = 255,
    GECHO = 1,
    GREPLY = 2
}

enum bit<8> LookupRespType {
    UE = 1,
    PDR = 2,
    UE_FLOW = 3,
    DEBUG = 6
}

#endif