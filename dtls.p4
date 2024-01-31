/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// Define constants for types of packets
#define PKT_INSTANCE_TYPE_NORMAL 0
#define PKT_INSTANCE_TYPE_INGRESS_CLONE 1
#define PKT_INSTANCE_TYPE_EGRESS_CLONE 2
#define PKT_INSTANCE_TYPE_COALESCED 3
#define PKT_INSTANCE_TYPE_INGRESS_RECIRC 4
#define PKT_INSTANCE_TYPE_REPLICATION 52
#define PKT_INSTANCE_TYPE_RESUBMIT 6

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> PROTOCOL_UDP = 0x11;
const bit<8> CTYPE_HSHAKE = 0x16;
const bit<8> zeross = 0x00;
const bit<8> TYPECERT1 = 0x02;
const bit<8> TYPECERT2 = 0x0b;
const bit<8> TYPECERT3 = 0x0c;
const bit<8> TYPECERT4 = 0x0e;
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<8> contentType_t;

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

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

header dtls_t {
    contentType_t contentType;
    bit<16> version;
    bit<16> epoch;
    bit<48> seqNumber;
    bit<16> lenDtls;
}

header dtlsH_SH_t {
    bit<8> SH;
}

struct metadata {
    bit<8> routecheck;
}

struct headers {
    ethernet_t              ethernet;
    ipv4_t                  ipv4;
    udp_t                   udp;
    dtls_t                  dtls;
    dtlsH_SH_t              dtlsHSH;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(standard_metadata.ingress_port) {
            0x01: parse_udp;
            0x02: parse_udp;
            0x03: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        transition select(hdr.ipv4.protocol) {
            PROTOCOL_UDP : parse_dtls;
            default: accept;
        }
    }

    state parse_dtls {
        packet.extract(hdr.udp);
        transition select(packet.lookahead<dtls_t>().contentType) {
            CTYPE_HSHAKE : parse_dtls_hshakeType;
            default: accept;
        }
    }

    state parse_dtls_hshakeType {
        packet.extract(hdr.dtls);
        transition select(packet.lookahead<bit<8>>()){
            0x02: parse_dtls_SH;
            0x0B: parse_dtls_SH;
            0x0C: parse_dtls_SH;
            0x0E: parse_dtls_SH;
            default: accept;
        }
    }

    state parse_dtls_SH {
        packet.extract(hdr.dtlsHSH);
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

    action forwardroute(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    table checkroute {
        key = {
            meta.routecheck: exact;
        }
        actions = {
            forwardroute;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if(hdr.dtls.isValid() && hdr.dtlsHSH.isValid()) {
            if(standard_metadata.ingress_port == 3) {
                meta.routecheck = 2;
                    ipv4_lpm.apply();

            }
            else if(hdr.dtlsHSH.SH == TYPECERT1) {
                meta.routecheck = 1;
                checkroute.apply();
            }
            else if(hdr.dtlsHSH.SH == TYPECERT2){
                meta.routecheck = 1;
                checkroute.apply();
            }
            else if(hdr.dtlsHSH.SH == TYPECERT3) {
                meta.routecheck = 1;
                checkroute.apply();
            }
            else if(hdr.dtlsHSH.SH == TYPECERT4){
                meta.routecheck = 1;
                checkroute.apply();
            }
            else {
                NoAction();
            }
        }
        else {
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
    apply {

    }
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

    update_checksum_with_payload(
        hdr.dtlsHSH.isValid(),
            { hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                zeross,
                hdr.ipv4.protocol,
                hdr.udp.length,
                hdr.udp.srcPort,
                hdr.udp.dstPort,
                hdr.udp.length,
                hdr.dtls.contentType,
                hdr.dtls.version,
                hdr.dtls.epoch,
                hdr.dtls.seqNumber,
                hdr.dtls.lenDtls,
                hdr.dtlsHSH.SH},
                hdr.udp.checksum,
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
        packet.emit(hdr.udp);
        packet.emit(hdr.dtls);
        packet.emit(hdr.dtlsHSH);
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
