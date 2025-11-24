/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define MAX_HOPS 10
#define PORTS 10

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> IP_PROTO = 253;

const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_NORMAL        = 0;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE = 1;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE  = 2;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_COALESCED     = 3;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RECIRC        = 4;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_REPLICATION   = 5;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RESUBMIT      = 6;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/


typedef bit<48> macAddr_v;
typedef bit<32> ip4Addr_v;

typedef bit<31> switchID_v;
typedef bit<9> ingress_port_v;
typedef bit<9> egress_port_v;
typedef bit<9>  egressSpec_v;
typedef bit<48>  ingress_global_timestamp_v;
typedef bit<48>  egress_global_timestamp_v;
typedef bit<32>  enq_timestamp_v;
typedef bit<19> enq_qdepth_v;
typedef bit<32> deq_timedelta_v;
typedef bit<19> deq_qdepth_v;

header ethernet_h {
    macAddr_v dstAddr;
    macAddr_v srcAddr;
    bit<16>   etherType;
}

header ipv4_h {
    bit<4>    version;
    bit<4>    ihl;
    bit<5>    diffserv;
    bit<1>    l4s;
    bit<2>    ecn;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_v srcAddr;
    ip4Addr_v dstAddr;
}

header nodeCount_h{
    bit<16>  count;
}

header InBandNetworkTelemetry_h {
    switchID_v swid;
    ingress_port_v ingress_port;
    egress_port_v egress_port;
    egressSpec_v egress_spec;
    ingress_global_timestamp_v ingress_global_timestamp;
    egress_global_timestamp_v egress_global_timestamp;
    enq_timestamp_v enq_timestamp;
    enq_qdepth_v enq_qdepth;
    deq_timedelta_v deq_timedelta;
    deq_qdepth_v deq_qdepth;
}

struct ingress_metadata_t {
    bit<16>  count;
}

struct parser_metadata_t {
    bit<16>  remaining;
}

struct queue_metadata_t {
    @field_list(0)
    bit<32> output_port;
}

struct metadata {
    ingress_metadata_t   ingress_metadata;
    parser_metadata_t   parser_metadata;
    queue_metadata_t    queue_metadata;
}

struct headers {
    ethernet_h         ethernet;
    ipv4_h             ipv4;
    nodeCount_h        nodeCount;
    InBandNetworkTelemetry_h[MAX_HOPS] INT;
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
            IP_PROTO: parse_count;
            default: accept;
        }
    }

    state parse_count{
        packet.extract(hdr.nodeCount);
        meta.parser_metadata.remaining = hdr.nodeCount.count;
        transition select(meta.parser_metadata.remaining) {
            0 : accept;
            default: parse_int;
        }
    }

    state parse_int {
        packet.extract(hdr.INT.next);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining  - 1;
        transition select(meta.parser_metadata.remaining) {
            0 : accept;
            default: parse_int;
        }
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
    


    register<bit<1>> (PORTS) flagtoDrop_reg; // Register ON/OFF drop action
    counter(4, CounterType.packets) forwardingPkt; // Counter forwarding packets
    counter(4, CounterType.packets) dropPkt; // Counter packets dropped by RED
    counter(4, CounterType.packets) dropRecirc; // Counter recirculated
    
    action drop_recirc() {
        dropRecirc.count(meta.queue_metadata.output_port); //increment the counter of recirculation packets dropped
        mark_to_drop(standard_metadata);
    }
    
    action drop_regular() {
        dropPkt.count((bit<32>)standard_metadata.egress_spec); //increment the counter of regular packets dropped
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_v dstAddr, egressSpec_v port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        forwardingPkt.count((bit<32>)standard_metadata.egress_spec); //increment the counter of packets fowarded
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop_regular;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    
    apply {

        if (standard_metadata.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_RECIRC) {
            
            //* Cloned pkts *//
            //* Turn ON congestion flag. Write '1' in the register index port *//
            flagtoDrop_reg.write(meta.queue_metadata.output_port,1); 
            
            //* Drop cloned pkt *//
            drop_recirc();
        
        }
        else {

            ipv4_lpm.apply();

            //* Read the output port state from the register*//
            bit<1> flag;
            flagtoDrop_reg.read(flag,(bit<32>)standard_metadata.egress_spec);

            //* Check if the congestion flag is 1 (Drop ON). *//
            if (flag == 1){            
                
                //* Not for L4S and INT! Only Classic *//
                if ((hdr.ipv4.l4s != 1) && (hdr.nodeCount.isValid() == false)){

                    standard_metadata.priority = (bit<3>)7;
                    
                    //* Reset *//
                    flagtoDrop_reg.write((bit<32>)standard_metadata.egress_spec,0);   
                    
                    //* Drop future packet *//
                    drop_regular();
                }
                
                if ((hdr.ipv4.l4s == 1) && (hdr.nodeCount.isValid() == false)){

                    standard_metadata.priority = (bit<3>)0;
                }     
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    register<bit<32>>(8) QueueID;
    register<bit<16>>(PORTS) dropProbability; // Register to save drop probability      
    register<bit<32>> (1) targetDelay_reg; // Register to store target delay. Initial value 20000us = 20ms  
    register<bit<32>>(PORTS) QDelay_reg; //Register to save queue delay           
    counter(4, CounterType.packets) recirc; // Counter recirculate pkts
    counter(4, CounterType.packets) cloneCount; // Counter clone pkts


    // Send again the packet through both pipelines
    action recirculate_packet(){
        recirculate_preserving_field_list(0);
        recirc.count(meta.queue_metadata.output_port);
    }

    action clonePacket(){
        clone_preserving_field_list(CloneType.E2E, meta.queue_metadata.output_port,0);
        cloneCount.count(meta.queue_metadata.output_port);
    }

    action add_swtrace(switchID_v swid) { 
        hdr.nodeCount.count = hdr.nodeCount.count + 1;
        hdr.INT.push_front(1);
        hdr.INT[0].setValid();
        hdr.INT[0].swid = swid;
        hdr.INT[0].ingress_port = (ingress_port_v)standard_metadata.ingress_port;
        hdr.INT[0].ingress_global_timestamp = (ingress_global_timestamp_v)standard_metadata.ingress_global_timestamp;
        hdr.INT[0].egress_port = (egress_port_v)standard_metadata.egress_port;
        hdr.INT[0].egress_spec = (egressSpec_v)standard_metadata.egress_spec;
        hdr.INT[0].egress_global_timestamp = (egress_global_timestamp_v)standard_metadata.egress_global_timestamp;
        hdr.INT[0].enq_timestamp = (enq_timestamp_v)standard_metadata.enq_timestamp;
        hdr.INT[0].enq_qdepth = (enq_qdepth_v)standard_metadata.enq_qdepth;
        hdr.INT[0].deq_timedelta = (deq_timedelta_v)standard_metadata.deq_timedelta;
        hdr.INT[0].deq_qdepth = (deq_qdepth_v)standard_metadata.deq_qdepth;
        
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 32;
    }

    table swtrace {
        actions = { 
	        add_swtrace; 
	        NoAction; 
        }
        default_action = NoAction();      
    }
    
    apply {
	
	QueueID.write((bit<32>)standard_metadata.qid, 1);
        
        //* Only INT packets *//    
        if (hdr.nodeCount.isValid()) {
        
            swtrace.apply();
        
        }
        
        //* Check IF is a clone pkt generated in the egress *//
        if (standard_metadata.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE) {
            
            meta.queue_metadata.output_port = (bit<32>)standard_metadata.egress_port;
            recirculate_packet();
        } 
        else { 

            //* Only regular (not cloned) packets enter here *//

            //* Read TARGET_DELAY from register updated by Control Plane *//
            //* register_write MyEgress.targetDelay_reg 0 20000 *//
            bit<32> TARGET_DELAY = 20000; 
            //targetDelay_reg.read(TARGET_DELAY,0);

            
            //* Get queue delay per packet after TM *//
            bit<32> qdelay = (bit<32>)standard_metadata.deq_timedelta;
        
            //* Previous Queue Delay by port used to compute moving average *//
            bit<32> previousQDelay;                       
            QDelay_reg.read(previousQDelay, (bit<32>)standard_metadata.egress_port);
            
            //* Compute Exponentially-Weighted Mean Average (EWMA) of queue delay *//
            // EWMA = alpha*qdelay + (1 - alpha)*previousEWMA
            // We use alpha = 0.5 such that multiplications can be replaced by bit shifts
            
            bit<32> EWMA = (qdelay>>1) + (previousQDelay>>1);

            //* Update register *//
            QDelay_reg.write((bit<32>)standard_metadata.egress_port, EWMA);
                                 
            //* Check if the queue delay reach the target limit *//
            //* 0 = no drop    *//
            //* 1 = Maybe drop *//
            //* 2 = drop       *//

            bit<8> target_violation;

            //* No drop *//
            if (EWMA <= TARGET_DELAY){
            
                target_violation = 0;
            
            }
            
            //* Maybe drop *//
            if ((EWMA > TARGET_DELAY) && (EWMA < (TARGET_DELAY<<1))){ 
            
                target_violation = 1;
            
            }

            //* Drop *//
            if (EWMA > (TARGET_DELAY<<1)){

                target_violation = 2;

            } 

            
            if (target_violation == 1) {

                bit<16> rand_classic;
                random(rand_classic, 0, 65535);
                bit<16> rand_l4s = rand_classic >> 1;
                bit<16> dropProb;
                bit<16> dropProb_temp;

                if (hdr.ipv4.l4s == 1){

                    bool mark_decision_l4s;
                    dropProbability.read(dropProb, (bit<32>)standard_metadata.egress_port);
                    
                    
                    //* Compute L4S mark probability *//
                    if (rand_l4s < dropProb){
                        
                        dropProb_temp = dropProb - 1;

                        dropProbability.write((bit<32>)standard_metadata.egress_port,dropProb_temp);
                        
                        mark_decision_l4s = true;

                    }else{

                        dropProb_temp = dropProb + 1;

                        dropProbability.write((bit<32>)standard_metadata.egress_port,dropProb_temp);

                        mark_decision_l4s = false;

                    }

                    //* Mark ECN bit to L4S traffic *//
                    if (mark_decision_l4s == true){
                        
                        hdr.ipv4.ecn = 3;    
                    
                    } 

                }else{

                    bool drop_decision_classic;
                    dropProbability.read(dropProb, (bit<32>)standard_metadata.egress_port);

                    //* Compute Classic drop probability *//
                    if (rand_classic < dropProb){
                        
                        dropProb_temp = dropProb - 1;

                        dropProbability.write((bit<32>)standard_metadata.egress_port,dropProb_temp);
                        
                        drop_decision_classic = true;

                    }else{

                        dropProb_temp = dropProb + 1;

                        dropProbability.write((bit<32>)standard_metadata.egress_port,dropProb_temp);

                        drop_decision_classic = false;

                    }


                    if (drop_decision_classic == true){
                        
                        meta.queue_metadata.output_port = (bit<32>)standard_metadata.egress_port;
                        clonePacket();

                    }
                }
                        
            }else if (target_violation == 2){

                //* Mark ECN bit to L4S traffic *//
                if (hdr.ipv4.l4s == 1){
                
                    hdr.ipv4.ecn = 3;

                }else{

                    meta.queue_metadata.output_port = (bit<32>)standard_metadata.egress_port;
                    clonePacket();
                
                }
            }
        }             
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
              hdr.ipv4.l4s,
              hdr.ipv4.ecn,
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
        packet.emit(hdr.nodeCount);
        packet.emit(hdr.INT);                
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
