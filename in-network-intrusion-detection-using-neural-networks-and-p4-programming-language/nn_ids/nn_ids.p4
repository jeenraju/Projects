// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> IP_PROTO_TCP = 6;
const bit<8> IP_PROTO_UDP = 17;
const bit<8> PROTO_ICMP = 1;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv6_t {
    bit<4>   version;
    bit<8>   trafficClass;
    bit<20>  flowLabel;
    bit<16>  payloadLen;    
    bit<8>   nextHdr;      
    bit<8>   hopLimit;      
    bit<128> srcAddr;
    bit<128> dstAddr;
}
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<9>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}


header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header icmp_t {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
    bit<32> rest;
}

header icmpv6_t {
    bit<8>  type;
    bit<8>  code;
    bit<16> checksum;
}

struct metadata {
    bit<32> proto;     // (5) IP protocol / next header
    bit<32> sttl;      // (10) TTL (IPv4) / hopLimit (IPv6)
    bit<32> dttl;      // (11) reverse direction TTL not available -> 0
    bit<32> swin;      // (19) TCP.window if TCP else 0
    bit<32> dwin;      // (20) reverse window not available -> 0
    bit<32> stcpb;     // (21) TCP seqNo if TCP else 0
    bit<32> dtcpb;     // (22) TCP ackNo if TCP else 0

    // H1 accumulators / activations / buckets
    int<64> h1_acc0; int<64> h1_acc1; int<64> h1_acc2; int<64> h1_acc3; int<64> h1_acc4;
    bit<32> h1_act0; bit<32> h1_act1; bit<32> h1_act2; bit<32> h1_act3; bit<32> h1_act4;
    bit<32> h1_bucket0; bit<32> h1_bucket1; bit<32> h1_bucket2; bit<32> h1_bucket3;    bit<32> h1_bucket4;

    // H2 accumulators / activations / buckets
    int<64> h2_acc0; int<64> h2_acc1; int<64> h2_acc2; int<64> h2_acc3; int<64> h2_acc4;
    bit<32> h2_act0; bit<32> h2_act1; bit<32> h2_act2; bit<32> h2_act3; bit<32> h2_act4;
    bit<32> h2_bucket0; bit<32> h2_bucket1; bit<32> h2_bucket2; bit<32> h2_bucket3; bit<32> h2_bucket4;
    
    int<64> out_acc_q;

    // scratch
    bit<32> idx_h1;
    bit<32> idx_h2;
    bit<1>  is_attack;

}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    ipv6_t       ipv6;
    tcp_t        tcp;
    udp_t        udp;
    icmp_t       icmp;
    icmpv6_t     icmpv6;
}


const bit<8> FRAC_BITS = 8w8;   // Q8.8: shift by 8, encoded as 8-bit literal
const bit<32> H1_SIZE   = 5;  // hidden layer 1 neurons
const bit<32> H2_SIZE   = 5;  // hidden layer 2 neurons

// Biases and threshold (all quantized ints)
register<bit<32>>(H1_SIZE) reg_b1_q;
register<bit<32>>(H2_SIZE) reg_b2_q;
register<bit<32>>(1)       reg_b3_q;
register<bit<32>>(1)       reg_thresh_q;

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            0x86dd:    parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
	    PROTO_ICMP: parse_icmp;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
            6:  parse_tcp;     
            17: parse_udp;     
            58: parse_icmpv6;  
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }
    state parse_icmpv6 {
        packet.extract(hdr.icmpv6);
        transition accept;
    } 	

}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
	
	standard_metadata.egress_spec = port;
	hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
	hdr.ethernet.dstAddr = dstAddr;
	hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
  

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
 
    action extract_packet_features() {
        /* Initialize to safe defaults */
        meta.proto    = 0;
        meta.sttl     = 0;
        meta.dttl     = 0;   // single direction only
        meta.swin     = 0;
        meta.dwin     = 0;   // single direction only
        meta.stcpb    = 0;
        meta.dtcpb    = 0;

        if (hdr.ipv4.isValid()) {
            meta.proto = (bit<32>) hdr.ipv4.protocol;
            meta.sttl  = (bit<32>) hdr.ipv4.ttl;

            if (hdr.tcp.isValid()) {
                meta.swin   = (bit<32>) hdr.tcp.window;
                meta.stcpb  = (bit<32>) hdr.tcp.seqNo;
                meta.dtcpb  = (bit<32>) hdr.tcp.ackNo;

            } 

        } else if (hdr.ipv6.isValid()) {
            meta.proto = (bit<32>) hdr.ipv6.nextHdr;
            meta.sttl  = (bit<32>) hdr.ipv6.hopLimit;

            if (hdr.tcp.isValid()) {
                meta.swin   = (bit<32>) hdr.tcp.window;
                meta.stcpb  = (bit<32>) hdr.tcp.seqNo;
                meta.dtcpb  = (bit<32>) hdr.tcp.ackNo;

            } 
        }
    }
    // Zero all accumulators
    action reset_accs() {
        meta.h1_acc0 = 0; meta.h1_acc1 = 0; meta.h1_acc2 = 0; meta.h1_acc3 = 0; meta.h1_acc4 = 0;
        meta.h2_acc0 = 0; meta.h2_acc1 = 0; meta.h2_acc2 = 0; meta.h2_acc3 = 0; meta.h2_acc4 = 0; meta.out_acc_q = 0;
    }
    // Seed H1 with biases
    action add_b1() {
        bit<32> b;
        reg_b1_q.read(b, 0); meta.h1_acc0 = (int<64>)((int<32>)b);
        reg_b1_q.read(b, 1); meta.h1_acc1 = (int<64>)((int<32>)b);
        reg_b1_q.read(b, 2); meta.h1_acc2 = (int<64>)((int<32>)b);
        reg_b1_q.read(b, 3); meta.h1_acc3 = (int<64>)((int<32>)b);
        reg_b1_q.read(b, 4); meta.h1_acc4 = (int<64>)((int<32>)b);
    }
    // Seed H2 with biases
    action add_b2() {
        bit<32> b;
        reg_b2_q.read(b, 0); meta.h2_acc0 = (int<64>)((int<32>)b);
        reg_b2_q.read(b, 1); meta.h2_acc1 = (int<64>)((int<32>)b);
        reg_b2_q.read(b, 2); meta.h2_acc2 = (int<64>)((int<32>)b);
        reg_b2_q.read(b, 3); meta.h2_acc3 = (int<64>)((int<32>)b);
        reg_b2_q.read(b, 4); meta.h2_acc4 = (int<64>)((int<32>)b);
    }
    // Seed OUT with bias
    action add_b3() {
        bit<32> b; reg_b3_q.read(b, 0);
        meta.out_acc_q = (int<64>)((int<32>)b);
    }
    // ReLU + downshift (to 32-bit Q)
    action relu_h1() {
       if (meta.h1_acc0 < 0) { meta.h1_acc0 = 0; }
       if (meta.h1_acc1 < 0) { meta.h1_acc1 = 0; }
       if (meta.h1_acc2 < 0) { meta.h1_acc2 = 0; }
       if (meta.h1_acc3 < 0) { meta.h1_acc3 = 0; }
       if (meta.h1_acc4 < 0) { meta.h1_acc4 = 0; }

        meta.h1_act0 = (bit<32>) (((bit<64>) meta.h1_acc0) >> FRAC_BITS);
        meta.h1_act1 = (bit<32>) (((bit<64>) meta.h1_acc1) >> FRAC_BITS);
        meta.h1_act2 = (bit<32>) (((bit<64>) meta.h1_acc2) >> FRAC_BITS);
        meta.h1_act3 = (bit<32>) (((bit<64>) meta.h1_acc3) >> FRAC_BITS);
        meta.h1_act4 = (bit<32>) (((bit<64>) meta.h1_acc4) >> FRAC_BITS);

        // same value used as bucket; you can quantize more if needed
        meta.h1_bucket0 = meta.h1_act0;
        meta.h1_bucket1 = meta.h1_act1;
        meta.h1_bucket2 = meta.h1_act2;
        meta.h1_bucket3 = meta.h1_act3;
        meta.h1_bucket4 = meta.h1_act4;
    }
    action relu_h2() {
        if (meta.h2_acc0 < 0) { meta.h2_acc0 = 0; }
        if (meta.h2_acc1 < 0) { meta.h2_acc1 = 0; }
        if (meta.h2_acc2 < 0) { meta.h2_acc2 = 0; }
        if (meta.h2_acc3 < 0) { meta.h2_acc3 = 0; }
        if (meta.h2_acc4 < 0) { meta.h2_acc4 = 0; }

        meta.h2_act0 = (bit<32>) (((bit<64>) meta.h2_acc0) >> FRAC_BITS);
        meta.h2_act1 = (bit<32>) (((bit<64>) meta.h2_acc1) >> FRAC_BITS);
        meta.h2_act2 = (bit<32>) (((bit<64>) meta.h2_acc2) >> FRAC_BITS);
        meta.h2_act3 = (bit<32>) (((bit<64>) meta.h2_acc3) >> FRAC_BITS);
        meta.h2_act4 = (bit<32>) (((bit<64>) meta.h2_acc4) >> FRAC_BITS);

        meta.h2_bucket0 = meta.h2_act0;
        meta.h2_bucket1 = meta.h2_act1;
        meta.h2_bucket2 = meta.h2_act2;
        meta.h2_bucket3 = meta.h2_act3;
        meta.h2_bucket4 = meta.h2_act4;
    }
    // Add product to H1 neuron k
    action add_to_h1_0(bit<32> prod_q32) { meta.h1_acc0 = meta.h1_acc0 + (int<64>)((int<32>)prod_q32); }
    action add_to_h1_1(bit<32> prod_q32) { meta.h1_acc1 = meta.h1_acc1 + (int<64>)((int<32>)prod_q32); }
    action add_to_h1_2(bit<32> prod_q32) { meta.h1_acc2 = meta.h1_acc2 + (int<64>)((int<32>)prod_q32); }
    action add_to_h1_3(bit<32> prod_q32) { meta.h1_acc3 = meta.h1_acc3 + (int<64>)((int<32>)prod_q32); }
    action add_to_h1_4(bit<32> prod_q32) { meta.h1_acc4 = meta.h1_acc4 + (int<64>)((int<32>)prod_q32); }

    // Add product to H2 neuron k
    action add_to_h2_0(bit<32> prod_q32) { meta.h2_acc0 = meta.h2_acc0 + (int<64>)((int<32>)prod_q32); }
    action add_to_h2_1(bit<32> prod_q32) { meta.h2_acc1 = meta.h2_acc1 + (int<64>)((int<32>)prod_q32); }
    action add_to_h2_2(bit<32> prod_q32) { meta.h2_acc2 = meta.h2_acc2 + (int<64>)((int<32>)prod_q32); }
    action add_to_h2_3(bit<32> prod_q32) { meta.h2_acc3 = meta.h2_acc3 + (int<64>)((int<32>)prod_q32); }
    action add_to_h2_4(bit<32> prod_q32) { meta.h2_acc4 = meta.h2_acc4 + (int<64>)((int<32>)prod_q32); }

    // Add product to OUTPUT
    action add_to_out(bit<32> prod_q32) { meta.out_acc_q = meta.out_acc_q + (int<64>)((int<32>)prod_q32); }

    // Final decision: drop on attack
    action decide_and_act() {
        bit<32> thr; reg_thresh_q.read(thr, 0);
        meta.is_attack = (meta.out_acc_q >= (int<64>)((int<32>)thr)) ? 1w1 : 1w0;
        if (meta.is_attack == 1w1) {
            mark_to_drop(standard_metadata);
        }
    }
    
    /* ---- Feature -> H1 (7 features × 5 neurons = 35 small tables) ---- */
    /* Keys are just the feature value; each table hard-wires the dest neuron via its    action. */

   

    /* proto */
    table t_f_proto_to_h1_0  { key = { meta.proto    : exact; } actions = { add_to_h1_0; NoAction; } size = 256;  }
    table t_f_proto_to_h1_1  { key = { meta.proto    : exact; } actions = { add_to_h1_1; NoAction; } size = 256;  }
    table t_f_proto_to_h1_2  { key = { meta.proto    : exact; } actions = { add_to_h1_2; NoAction; } size = 256;  }
    table t_f_proto_to_h1_3  { key = { meta.proto    : exact; } actions = { add_to_h1_3; NoAction; } size = 256;  }
    table t_f_proto_to_h1_4  { key = { meta.proto    : exact; } actions = { add_to_h1_4; NoAction; } size = 256;  }

    /* sttl */
    table t_f_sttl_to_h1_0   { key = { meta.sttl     : exact; } actions = { add_to_h1_0; NoAction; } size = 256;  }
    table t_f_sttl_to_h1_1   { key = { meta.sttl     : exact; } actions = { add_to_h1_1; NoAction; } size = 256;  }
    table t_f_sttl_to_h1_2   { key = { meta.sttl     : exact; } actions = { add_to_h1_2; NoAction; } size = 256;  }
    table t_f_sttl_to_h1_3   { key = { meta.sttl     : exact; } actions = { add_to_h1_3; NoAction; } size = 256;  }
    table t_f_sttl_to_h1_4   { key = { meta.sttl     : exact; } actions = { add_to_h1_4; NoAction; } size = 256;  }

    /* dttl */
    table t_f_dttl_to_h1_0   { key = { meta.dttl     : exact; } actions = { add_to_h1_0; NoAction; } size = 8;    }
    table t_f_dttl_to_h1_1   { key = { meta.dttl     : exact; } actions = { add_to_h1_1; NoAction; } size = 8;    }
    table t_f_dttl_to_h1_2   { key = { meta.dttl     : exact; } actions = { add_to_h1_2; NoAction; } size = 8;    }
    table t_f_dttl_to_h1_3   { key = { meta.dttl     : exact; } actions = { add_to_h1_3; NoAction; } size = 8;    }
    table t_f_dttl_to_h1_4   { key = { meta.dttl     : exact; } actions = { add_to_h1_4; NoAction; } size = 8;    }

    /* swin */
    table t_f_swin_to_h1_0   { key = { meta.swin     : exact; } actions = { add_to_h1_0; NoAction; } size = 4096; }
    table t_f_swin_to_h1_1   { key = { meta.swin     : exact; } actions = { add_to_h1_1; NoAction; } size = 4096; }
    table t_f_swin_to_h1_2   { key = { meta.swin     : exact; } actions = { add_to_h1_2; NoAction; } size = 4096; }
    table t_f_swin_to_h1_3   { key = { meta.swin     : exact; } actions = { add_to_h1_3; NoAction; } size = 4096; }
    table t_f_swin_to_h1_4   { key = { meta.swin     : exact; } actions = { add_to_h1_4; NoAction; } size = 4096; }

    /* dwin */
    table t_f_dwin_to_h1_0   { key = { meta.dwin     : exact; } actions = { add_to_h1_0; NoAction; } size = 8;    }
    table t_f_dwin_to_h1_1   { key = { meta.dwin     : exact; } actions = { add_to_h1_1; NoAction; } size = 8;    }
    table t_f_dwin_to_h1_2   { key = { meta.dwin     : exact; } actions = { add_to_h1_2; NoAction; } size = 8;    }
    table t_f_dwin_to_h1_3   { key = { meta.dwin     : exact; } actions = { add_to_h1_3; NoAction; } size = 8;    }
    table t_f_dwin_to_h1_4   { key = { meta.dwin     : exact; } actions = { add_to_h1_4; NoAction; } size = 8;    }

    /* stcpb */
    table t_f_stcpb_to_h1_0  { key = { meta.stcpb    : exact; } actions = { add_to_h1_0; NoAction; } size = 4096; }
    table t_f_stcpb_to_h1_1  { key = { meta.stcpb    : exact; } actions = { add_to_h1_1; NoAction; } size = 4096; }
    table t_f_stcpb_to_h1_2  { key = { meta.stcpb    : exact; } actions = { add_to_h1_2; NoAction; } size = 4096; }
    table t_f_stcpb_to_h1_3  { key = { meta.stcpb    : exact; } actions = { add_to_h1_3; NoAction; } size = 4096; }
    table t_f_stcpb_to_h1_4  { key = { meta.stcpb    : exact; } actions = { add_to_h1_4; NoAction; } size = 4096; }

    /* dtcpb */
    table t_f_dtcpb_to_h1_0  { key = { meta.dtcpb    : exact; } actions = { add_to_h1_0; NoAction; } size = 4096; }
    table t_f_dtcpb_to_h1_1  { key = { meta.dtcpb    : exact; } actions = { add_to_h1_1; NoAction; } size = 4096; }
    table t_f_dtcpb_to_h1_2  { key = { meta.dtcpb    : exact; } actions = { add_to_h1_2; NoAction; } size = 4096; }
    table t_f_dtcpb_to_h1_3  { key = { meta.dtcpb    : exact; } actions = { add_to_h1_3; NoAction; } size = 4096; }
    table t_f_dtcpb_to_h1_4  { key = { meta.dtcpb    : exact; } actions = { add_to_h1_4; NoAction; } size = 4096; }



    /* ---- H1 -> H2 (5 sources × 5 dests = 25 small tables) ---- */
    /* Each table is applied once; key is the source H1 bucket; action fixes the dest neuron. */

    table t_h1_0_to_h2_0 { key = { meta.h1_bucket0 : exact; } actions = { add_to_h2_0; NoAction; } size = 4096; }
    table t_h1_0_to_h2_1 { key = { meta.h1_bucket0 : exact; } actions = { add_to_h2_1; NoAction; } size = 4096; }
    table t_h1_0_to_h2_2 { key = { meta.h1_bucket0 : exact; } actions = { add_to_h2_2; NoAction; } size = 4096; }
    table t_h1_0_to_h2_3 { key = { meta.h1_bucket0 : exact; } actions = { add_to_h2_3; NoAction; } size = 4096; }
    table t_h1_0_to_h2_4 { key = { meta.h1_bucket0 : exact; } actions = { add_to_h2_4; NoAction; } size = 4096; }

    table t_h1_1_to_h2_0 { key = { meta.h1_bucket1 : exact; } actions = { add_to_h2_0; NoAction; } size = 4096; }
    table t_h1_1_to_h2_1 { key = { meta.h1_bucket1 : exact; } actions = { add_to_h2_1; NoAction; } size = 4096; }
    table t_h1_1_to_h2_2 { key = { meta.h1_bucket1 : exact; } actions = { add_to_h2_2; NoAction; } size = 4096; }
    table t_h1_1_to_h2_3 { key = { meta.h1_bucket1 : exact; } actions = { add_to_h2_3; NoAction; } size = 4096; }
    table t_h1_1_to_h2_4 { key = { meta.h1_bucket1 : exact; } actions = { add_to_h2_4; NoAction; } size = 4096; }

    table t_h1_2_to_h2_0 { key = { meta.h1_bucket2 : exact; } actions = { add_to_h2_0; NoAction; } size = 4096; }
    table t_h1_2_to_h2_1 { key = { meta.h1_bucket2 : exact; } actions = { add_to_h2_1; NoAction; } size = 4096; }
    table t_h1_2_to_h2_2 { key = { meta.h1_bucket2 : exact; } actions = { add_to_h2_2; NoAction; } size = 4096; }
    table t_h1_2_to_h2_3 { key = { meta.h1_bucket2 : exact; } actions = { add_to_h2_3; NoAction; } size = 4096; }
    table t_h1_2_to_h2_4 { key = { meta.h1_bucket2 : exact; } actions = { add_to_h2_4; NoAction; } size = 4096; }

    table t_h1_3_to_h2_0 { key = { meta.h1_bucket3 : exact; } actions = { add_to_h2_0; NoAction; } size = 4096; }
    table t_h1_3_to_h2_1 { key = { meta.h1_bucket3 : exact; } actions = { add_to_h2_1; NoAction; } size = 4096; }
    table t_h1_3_to_h2_2 { key = { meta.h1_bucket3 : exact; } actions = { add_to_h2_2; NoAction; } size = 4096; }
    table t_h1_3_to_h2_3 { key = { meta.h1_bucket3 : exact; } actions = { add_to_h2_3; NoAction; } size = 4096; }
    table t_h1_3_to_h2_4 { key = { meta.h1_bucket3 : exact; } actions = { add_to_h2_4; NoAction; } size = 4096; }

    table t_h1_4_to_h2_0 { key = { meta.h1_bucket4 : exact; } actions = { add_to_h2_0; NoAction; } size = 4096; }
    table t_h1_4_to_h2_1 { key = { meta.h1_bucket4 : exact; } actions = { add_to_h2_1; NoAction; } size = 4096; }
    table t_h1_4_to_h2_2 { key = { meta.h1_bucket4 : exact; } actions = { add_to_h2_2; NoAction; } size = 4096; }
    table t_h1_4_to_h2_3 { key = { meta.h1_bucket4 : exact; } actions = { add_to_h2_3; NoAction; } size = 4096; }
    table t_h1_4_to_h2_4 { key = { meta.h1_bucket4 : exact; } actions = { add_to_h2_4; NoAction; } size = 4096; }

    /* ---- H2 -> OUT (5 tables, one per H2 source) ---- */
    table t_h2_0_to_out { key = { meta.h2_bucket0 : exact; } actions = { add_to_out; NoAction; } size = 4096; }
    table t_h2_1_to_out { key = { meta.h2_bucket1 : exact; } actions = { add_to_out; NoAction; } size = 4096; }
    table t_h2_2_to_out { key = { meta.h2_bucket2 : exact; } actions = { add_to_out; NoAction; } size = 4096; }
    table t_h2_3_to_out { key = { meta.h2_bucket3 : exact; } actions = { add_to_out; NoAction; } size = 4096; }
    table t_h2_4_to_out { key = { meta.h2_bucket4 : exact; } actions = { add_to_out; NoAction; } size = 4096; }


    apply {
       // 0) Inputs
       extract_packet_features();

       // 1) Init + H1 bias
       reset_accs();
       add_b1();

       // 2) Layer 1 — apply each feature→H1 table exactly once per neuron

       // H1 neuron 0
       t_f_proto_to_h1_0.apply();
       t_f_sttl_to_h1_0.apply();
       t_f_dttl_to_h1_0.apply();
       t_f_swin_to_h1_0.apply();
       t_f_dwin_to_h1_0.apply();
       t_f_stcpb_to_h1_0.apply();
       t_f_dtcpb_to_h1_0.apply();

       // H1 neuron 1
       t_f_proto_to_h1_1.apply();
       t_f_sttl_to_h1_1.apply();
       t_f_dttl_to_h1_1.apply();
       t_f_swin_to_h1_1.apply();
       t_f_dwin_to_h1_1.apply();
       t_f_stcpb_to_h1_1.apply();
       t_f_dtcpb_to_h1_1.apply();

       // H1 neuron 2
       t_f_proto_to_h1_2.apply();
       t_f_sttl_to_h1_2.apply();
       t_f_dttl_to_h1_2.apply();
       t_f_swin_to_h1_2.apply();
       t_f_dwin_to_h1_2.apply();
       t_f_stcpb_to_h1_2.apply();
       t_f_dtcpb_to_h1_2.apply();

       // H1 neuron 3
       t_f_proto_to_h1_3.apply();
       t_f_sttl_to_h1_3.apply();
       t_f_dttl_to_h1_3.apply();
       t_f_swin_to_h1_3.apply();
       t_f_dwin_to_h1_3.apply();
       t_f_stcpb_to_h1_3.apply();
       t_f_dtcpb_to_h1_3.apply();

       // H1 neuron 4
       t_f_proto_to_h1_4.apply();
       t_f_sttl_to_h1_4.apply();
       t_f_dttl_to_h1_4.apply();
       t_f_swin_to_h1_4.apply();
       t_f_dwin_to_h1_4.apply();
       t_f_stcpb_to_h1_4.apply();
       t_f_dtcpb_to_h1_4.apply();

       // 3) ReLU + bucket H1
       relu_h1();

       // 4) Init H2 with bias
       add_b2();

       // 5) Layer 2 — apply each H1[i]→H2[j] table exactly once

       // from H1[0]
       t_h1_0_to_h2_0.apply();
       t_h1_0_to_h2_1.apply();
       t_h1_0_to_h2_2.apply();
       t_h1_0_to_h2_3.apply();
       t_h1_0_to_h2_4.apply();

       // from H1[1]
       t_h1_1_to_h2_0.apply();
       t_h1_1_to_h2_1.apply();
       t_h1_1_to_h2_2.apply();
       t_h1_1_to_h2_3.apply();
       t_h1_1_to_h2_4.apply();

       // from H1[2]
       t_h1_2_to_h2_0.apply();
       t_h1_2_to_h2_1.apply();
       t_h1_2_to_h2_2.apply();
       t_h1_2_to_h2_3.apply();
       t_h1_2_to_h2_4.apply();

       // from H1[3]
       t_h1_3_to_h2_0.apply();
       t_h1_3_to_h2_1.apply();
       t_h1_3_to_h2_2.apply();
       t_h1_3_to_h2_3.apply();
       t_h1_3_to_h2_4.apply();

       // from H1[4]
       t_h1_4_to_h2_0.apply();
       t_h1_4_to_h2_1.apply();
       t_h1_4_to_h2_2.apply();
       t_h1_4_to_h2_3.apply();
       t_h1_4_to_h2_4.apply();   

        // 6) ReLU + bucket H2
        relu_h2();

        // 7) Init output with bias
        add_b3();

        // 8) Output: from each H2 source to OUT
        t_h2_0_to_out.apply();
        t_h2_1_to_out.apply();
        t_h2_2_to_out.apply();
        t_h2_3_to_out.apply();
        t_h2_4_to_out.apply();

        // 9) Decide and act (drop on attack)
        decide_and_act();

        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }

}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
	packet.emit(hdr.ethernet);
	packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.icmp);
        packet.emit(hdr.icmpv6);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;