#ifndef _HASH_COLLISION_SOL_
#define _HASH_COLLISION_SOL_

control HashCollisionSol(inout headers_t hdr, inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
        // simply drop the packet for now
        ig_dprsr_md.drop_ctl = 0x1;
    }
}

#endif 
