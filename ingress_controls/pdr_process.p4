#ifndef _PDR_MATCH_
#define _PDR_MATCH_

#include "../include/configuration.p4"
//#include "../ingress_controls/fetch_rule.p4"

control PDRMatch(inout headers_t hdr, inout bit<8> pdr_match_code) {
    
    apply { 
        // pdr0 
        // 0 indicates unspecified fields
        bool pdr_matched = false; 
        if (hdr.pdr0.qfi == 0 || hdr.pdr0.qfi == hdr.packet_pdr_key.qfi) {
            if (hdr.pdr0.ue_port == 0 || hdr.pdr0.ue_port == hdr.packet_pdr_key.ue_port) {
                if (hdr.pdr0.inet_port == 0 || hdr.pdr0.inet_port == hdr.packet_pdr_key.inet_port) {
                    if (hdr.pdr0.ue_addr == 0 || hdr.pdr0.ue_addr == hdr.packet_pdr_key.ue_addr) {
                        if (hdr.pdr0.inet_addr == 0 || hdr.pdr0.inet_addr == hdr.packet_pdr_key.inet_addr) {
                            pdr_matched = true;
                            // execute pdr actions
                            // we randomly forward each packet to a port for the test
                            // far
                            if (hdr.pdr0.needs_dropping) {
                                ;
                            }
                            else {
                                ;
                            }

                        }
                    }
                }
            }
        }
        // pdr1
        if (!pdr_matched) {
            if (hdr.pdr1.qfi == 0 || hdr.pdr1.qfi == hdr.packet_pdr_key.qfi) {
                if (hdr.pdr1.ue_port == 0 || hdr.pdr1.ue_port == hdr.packet_pdr_key.ue_port) {
                    if (hdr.pdr1.inet_port == 0 || hdr.pdr1.inet_port == hdr.packet_pdr_key.inet_port) {
                        if (hdr.pdr1.ue_addr == 0 || hdr.pdr1.ue_addr == hdr.packet_pdr_key.ue_addr) {
                            if (hdr.pdr1.inet_addr == 0 || hdr.pdr1.inet_addr == hdr.packet_pdr_key.inet_addr) {
                                pdr_matched = true;
                                // execute pdr actions
                                // we randomly forward each packet to a port for the test
                                // far
                                if (hdr.pdr0.needs_dropping) {
                                    ;
                                }
                                else {
                                    ;
                                }
                            }
                        }
                    }
                }
            }
        }
        // pdr2
        if (!pdr_matched) {
            if (hdr.pdr2.qfi == 0 || hdr.pdr2.qfi == hdr.packet_pdr_key.qfi) {
                if (hdr.pdr2.ue_port == 0 || hdr.pdr2.ue_port == hdr.packet_pdr_key.ue_port) {
                    if (hdr.pdr2.inet_port == 0 || hdr.pdr2.inet_port == hdr.packet_pdr_key.inet_port) {
                        if (hdr.pdr2.ue_addr == 0 || hdr.pdr2.ue_addr == hdr.packet_pdr_key.ue_addr) {
                            if (hdr.pdr2.inet_addr == 0 || hdr.pdr2.inet_addr == hdr.packet_pdr_key.inet_addr) {
                                pdr_matched = true;
                                // execute pdr actions
                                // we randomly forward each packet to a port for the test
                                // far
                                if (hdr.pdr0.needs_dropping) {
                                    ;
                                }
                                else {
                                    ;
                                }
                            }
                        }
                    }
                }
            }
        }
        // pdr3
        if (!pdr_matched) {
            if (hdr.pdr3.qfi == 0 || hdr.pdr3.qfi == hdr.packet_pdr_key.qfi) {
                if (hdr.pdr3.ue_port == 0 || hdr.pdr3.ue_port == hdr.packet_pdr_key.ue_port) {
                    if (hdr.pdr3.inet_port == 0 || hdr.pdr3.inet_port == hdr.packet_pdr_key.inet_port) {
                        if (hdr.pdr3.ue_addr == 0 || hdr.pdr3.ue_addr == hdr.packet_pdr_key.ue_addr) {
                            if (hdr.pdr3.inet_addr == 0 || hdr.pdr3.inet_addr == hdr.packet_pdr_key.inet_addr) {
                                pdr_matched = true;
                                // execute pdr actions
                                // we randomly forward each packet to a port for the test
                                // far
                                if (hdr.pdr0.needs_dropping) {
                                    ;
                                }
                                else {
                                    ;
                                }
                            }
                        }
                    }
                }
            }
        }
        // pdr4
        if (!pdr_matched) {
            if (hdr.pdr4.qfi == 0 || hdr.pdr4.qfi == hdr.packet_pdr_key.qfi) {
                if (hdr.pdr4.ue_port == 0 || hdr.pdr4.ue_port == hdr.packet_pdr_key.ue_port) {
                    if (hdr.pdr4.inet_port == 0 || hdr.pdr4.inet_port == hdr.packet_pdr_key.inet_port) {
                        if (hdr.pdr4.ue_addr == 0 || hdr.pdr4.ue_addr == hdr.packet_pdr_key.ue_addr) {
                            if (hdr.pdr4.inet_addr == 0 || hdr.pdr4.inet_addr == hdr.packet_pdr_key.inet_addr) {
                                pdr_matched = true;
                                // execute pdr actions
                                // we randomly forward each packet to a port for the test
                                // far
                                if (hdr.pdr0.needs_dropping) {
                                    ;
                                }
                                else {
                                    ;
                                }
                            }
                        }
                    }
                }
            }
        }

        /* [for test] force each packet to go through MAX_NUM_FETCH of iterations*/
        if (hdr.next_fetch_info.pdr_fetch_round_id == hdr.packet_ue_key.teid) {
            pdr_match_code = 2;
        }
        else {
            pdr_match_code = 0;
        }

    }
}

#endif 
