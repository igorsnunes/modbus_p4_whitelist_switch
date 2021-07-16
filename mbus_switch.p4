/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

const bit<8>  TYPE_TCP  = 6;
/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<48> time_t;
#define MAX_PORTS 100
const bit<16> MODBUS_TCP_PORT = 5020;
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

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}
header mbap_t {
    bit<16>   transaction_id;
    bit<16>   protocol_id;
    bit<16>   length;
    bit<8>    unit_id;
    bit<8>    fcode;
}
struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    mbap_t       mbap;
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
        transition select(hdr.ipv4.protocol){
            TYPE_TCP: parse_tcp;
            default: accept;
        }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition select(hdr.tcp.dstPort |  hdr.tcp.srcPort) {
            5020 : parse_mbap;
            5020 : parse_mbap;
            default: accept;
        }
    }
    state parse_mbap {
        packet.extract(hdr.mbap);
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

    counter(255, CounterType.packets_and_bytes) ingressMbapCounterHit;
    counter(255, CounterType.packets_and_bytes) ingressMbapCounterDrop;
    bool to_drop = false;
    register<bit<9>>(250) map_in_eg_port;
    bit<9> master_port;
    bit<9> slave_port;

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
        default_action = drop();
    }
    action read_ports_from_registers_dst() {
        map_in_eg_port.read(master_port, (bit<32>)standard_metadata.ingress_port);
        map_in_eg_port.read(slave_port, (bit<32>)standard_metadata.egress_spec);
    }
    table is_dst_port_mbus_table {
        key = { hdr.tcp.dstPort : exact; }
        actions = { read_ports_from_registers_dst; }
        const entries = { 5020 : read_ports_from_registers_dst; }
    }
    action read_ports_from_registers_src() {
        map_in_eg_port.read(slave_port, (bit<32>)standard_metadata.ingress_port);
        map_in_eg_port.read(master_port, (bit<32>)standard_metadata.egress_spec);
    }
    table is_src_port_mbus_table {
        key = { hdr.tcp.srcPort : exact; }
        actions = { read_ports_from_registers_src; }
        const entries = { 5020 : read_ports_from_registers_src; }
    }
    action update_master() {
        map_in_eg_port.write((bit<32>)standard_metadata.ingress_port, 255);
    }
    table filter_to_slaves_table {
        key = { master_port : exact; }
        actions = { NoAction; update_master; drop; }
        const entries = { 255 : NoAction(); 0 : update_master(); } 
        default_action = drop;
    }
    action update_slave() {
        map_in_eg_port.write((bit<32>)standard_metadata.ingress_port, standard_metadata.egress_spec);
    }
    table filter_to_master_table {
        key = { slave_port : exact; }
        actions = { NoAction; update_slave; drop; }
        const entries = { 255 : drop(); 0 : update_slave(); } 
        default_action = NoAction;
    }
    table shoud_drop_table {
        key = { master_port : exact; }
        actions = { NoAction; drop; }
        const entries = { 255 : NoAction; }
        default_action = drop;
    }
    action WhiteListAndCount() {
        ingressMbapCounterHit.count((bit<32>) standard_metadata.ingress_port);
    }
    action DropAndCount() {
        ingressMbapCounterDrop.count((bit<32>) standard_metadata.ingress_port);
        mark_to_drop(standard_metadata);
    }
    table whitelist_mbap_pkts_table {
        key = { hdr.ipv4.dstAddr : exact;
                hdr.mbap.fcode : exact ;
                hdr.mbap.unit_id : exact; }
        actions = { WhiteListAndCount; DropAndCount;}
        default_action = DropAndCount;
        size = 1024;
    }
    apply {
        master_port = 0;
        slave_port = 0;
        if (true/*hdr.ipv4.isValid()*/)
        {
            if (ipv4_lpm.apply().hit) {
                if (hdr.tcp.isValid()) {
                    if (is_dst_port_mbus_table.apply().hit) {
                        filter_to_slaves_table.apply();
                        if (hdr.tcp.fin ==  0 && hdr.tcp.syn == 0 && hdr.tcp.rst == 0) {
                            whitelist_mbap_pkts_table.apply();
                        }
                    }
                    else if (is_src_port_mbus_table.apply().hit) {
                        filter_to_master_table.apply();
                        shoud_drop_table.apply();
                        if (slave_port != standard_metadata.egress_spec)
                        {
                            drop();
                        }
                        else if (hdr.tcp.fin ==  0 && hdr.tcp.syn == 0 && hdr.tcp.rst == 0) {
                            whitelist_mbap_pkts_table.apply();
                        }
                    }
                }
            }
            else {
                drop();
            }
        }
        else
        {
           mark_to_drop(standard_metadata);
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

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
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
        packet.emit(hdr.tcp);
        packet.emit(hdr.mbap);
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
