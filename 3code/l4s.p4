/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define PORTS 10
#define MAX_FLOWS 256  // Número de fluxos simultâneos para IAT

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> PROTO_TCP = 6;

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

header ethernet_h {
    macAddr_v dstAddr;
    macAddr_v srcAddr;
    bit<16>   etherType;
}

header ipv4_h {
    bit<4>    version;
    bit<4>    ihl;
    bit<5>    diffserv;
    bit<1>    l4s;           // Bit L4S extraído do DSCP
    bit<2>    ecn;           // ECN bits
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

header tcp_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

struct queue_metadata_t {
    @field_list(0)
    bit<32> output_port;
}

struct metadata {
    queue_metadata_t queue_metadata;
}

struct headers {
    ethernet_h ethernet;
    ipv4_h     ipv4;
    tcp_h      tcp;
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
            PROTO_TCP: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
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
    
    // Registradores para controle de congestionamento
    register<bit<1>>(PORTS) flagtoDrop_reg;
    counter(4, CounterType.packets) forwardingPkt;
    counter(4, CounterType.packets) dropPkt;
    counter(4, CounterType.packets) dropRecirc;
    
    // ========== REGISTRADORES PARA IAT/IPI POR FLUXO ==========
    // Identificação do fluxo (5-tupla)
    register<bit<32>>(MAX_FLOWS) flow_src_ip;
    register<bit<32>>(MAX_FLOWS) flow_dst_ip;
    register<bit<16>>(MAX_FLOWS) flow_src_port;
    register<bit<16>>(MAX_FLOWS) flow_dst_port;
    register<bit<8>>(MAX_FLOWS)  flow_protocol;
    
    // Métricas do fluxo
    register<bit<48>>(MAX_FLOWS) flow_iat;              // IAT em microsegundos
    register<bit<48>>(MAX_FLOWS) flow_last_timestamp;   // Timestamp do último pacote
    register<bit<64>>(MAX_FLOWS) flow_packet_count;     // Total de pacotes do fluxo
    register<bit<1>>(MAX_FLOWS)  flow_is_l4s;           // 1=L4S, 0=Classic
    
    action drop_recirc() {
        dropRecirc.count(meta.queue_metadata.output_port);
        mark_to_drop(standard_metadata);
    }
    
    action drop_regular() {
        dropPkt.count((bit<32>)standard_metadata.egress_spec);
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_v dstAddr, bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        forwardingPkt.count((bit<32>)standard_metadata.egress_spec);
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
        // ========== TRATAMENTO DE RECIRCULAÇÃO ==========
        if (standard_metadata.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_RECIRC) {
            flagtoDrop_reg.write(meta.queue_metadata.output_port, 1); 
            drop_recirc();
        }
        else {
            // ========== ROTEAMENTO IPV4 ==========
            ipv4_lpm.apply();

            // ========== CÁLCULO DE IAT POR FLUXO ==========
            if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
                
                // Extrair portas TCP
                bit<16> src_port = hdr.tcp.srcPort;
                bit<16> dst_port = hdr.tcp.dstPort;
                
                // Calcular hash da 5-tupla para identificar fluxo
                bit<32> flow_hash;
                hash(flow_hash, 
                     HashAlgorithm.crc32,
                     (bit<32>)0,
                     {hdr.ipv4.srcAddr,
                      hdr.ipv4.dstAddr,
                      src_port,
                      dst_port,
                      hdr.ipv4.protocol},
                     (bit<32>)MAX_FLOWS);
                
                // Obter timestamp atual (em microsegundos)
                bit<48> current_ts = standard_metadata.ingress_global_timestamp;
                
                // Ler timestamp do último pacote deste fluxo
                bit<48> last_ts;
                flow_last_timestamp.read(last_ts, flow_hash);
                
                // Calcular IAT (Inter-Arrival Time) se não for o primeiro pacote
                if (last_ts != 0) {
                    bit<48> iat = current_ts - last_ts;
                    flow_iat.write(flow_hash, iat);
                } else {
                    // Primeiro pacote do fluxo: armazenar informações
                    flow_src_ip.write(flow_hash, hdr.ipv4.srcAddr);
                    flow_dst_ip.write(flow_hash, hdr.ipv4.dstAddr);
                    flow_src_port.write(flow_hash, src_port);
                    flow_dst_port.write(flow_hash, dst_port);
                    flow_protocol.write(flow_hash, hdr.ipv4.protocol);
                    flow_is_l4s.write(flow_hash, hdr.ipv4.l4s);
                    flow_iat.write(flow_hash, 0);
                }
                
                // Atualizar timestamp e contador de pacotes
                flow_last_timestamp.write(flow_hash, current_ts);
                bit<64> pkt_count;
                flow_packet_count.read(pkt_count, flow_hash);
                flow_packet_count.write(flow_hash, pkt_count + 1);
            }

            // ========== CONTROLE DE CONGESTIONAMENTO ==========
            // Lê flag de congestionamento da porta de saída
            bit<1> flag;
            flagtoDrop_reg.read(flag, (bit<32>)standard_metadata.egress_spec);

            // Se há congestionamento (flag == 1)
            if (flag == 1){            
                // Tráfego Classic: drop e baixa prioridade
                if (hdr.ipv4.l4s != 1){
                    standard_metadata.priority = (bit<3>)7;  // Fila de baixa prioridade
                    flagtoDrop_reg.write((bit<32>)standard_metadata.egress_spec, 0);   
                    drop_regular();
                }
                
                // Tráfego L4S: alta prioridade (será marcado com ECN no egress)
                if (hdr.ipv4.l4s == 1){
                    standard_metadata.priority = (bit<3>)0;  // Fila de alta prioridade
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
    register<bit<16>>(PORTS) dropProbability;
    register<bit<32>>(PORTS) QDelay_reg;
    counter(4, CounterType.packets) recirc;
    counter(4, CounterType.packets) cloneCount;

    action recirculate_packet(){
        recirculate_preserving_field_list(0);
        recirc.count(meta.queue_metadata.output_port);
    }

    action clonePacket(){
        clone_preserving_field_list(CloneType.E2E, meta.queue_metadata.output_port, 0);
        cloneCount.count(meta.queue_metadata.output_port);
    }
    
    apply {
        // Registra uso da fila
        QueueID.write((bit<32>)standard_metadata.qid, 1);
        
        // ========== TRATAMENTO DE CLONAGEM (DROP) ==========
        if (standard_metadata.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE) {
            meta.queue_metadata.output_port = (bit<32>)standard_metadata.egress_port;
            recirculate_packet();
        } 
        else { 
            // ========== CONTROLE DE CONGESTIONAMENTO BASEADO EM DELAY ==========
            bit<32> TARGET_DELAY = 20000;  // 20ms em microsegundos
            bit<32> qdelay = (bit<32>)standard_metadata.deq_timedelta;
            bit<32> previousQDelay;
            QDelay_reg.read(previousQDelay, (bit<32>)standard_metadata.egress_port);
            
            // EWMA: Exponential Weighted Moving Average
            bit<32> EWMA = (qdelay>>1) + (previousQDelay>>1);
            QDelay_reg.write((bit<32>)standard_metadata.egress_port, EWMA);
                                 
            // Classificar nível de congestionamento
            bit<8> target_violation = 0;  // Inicializar com valor padrão

            if (EWMA <= TARGET_DELAY){
                target_violation = 0;  // Sem congestionamento
            }
            else if ((EWMA > TARGET_DELAY) && (EWMA < (TARGET_DELAY<<1))){ 
                target_violation = 1;  // Congestionamento moderado
            }
            else if (EWMA >= (TARGET_DELAY<<1)){
                target_violation = 2;  // Congestionamento severo
            } 

            // ========== REAÇÃO AO CONGESTIONAMENTO ==========
            if (target_violation == 1) {
                // Gerar números aleatórios para decisão probabilística
                bit<16> rand_classic;
                random(rand_classic, 0, 65535);
                bit<16> rand_l4s = rand_classic >> 1;  // L4S: metade da probabilidade
                bit<16> dropProb;
                bit<16> dropProb_temp;

                // ========== TRÁFEGO L4S: MARCAÇÃO ECN ==========
                if (hdr.ipv4.l4s == 1){
                    bool mark_decision_l4s;
                    dropProbability.read(dropProb, (bit<32>)standard_metadata.egress_port);
                    
                    // Decisão probabilística de marcação
                    if (rand_l4s < dropProb){
                        dropProb_temp = dropProb - 1;
                        dropProbability.write((bit<32>)standard_metadata.egress_port, dropProb_temp);
                        mark_decision_l4s = true;
                    } else {
                        dropProb_temp = dropProb + 1;
                        dropProbability.write((bit<32>)standard_metadata.egress_port, dropProb_temp);
                        mark_decision_l4s = false;
                    }

                    // Marcar ECN (Congestion Experienced)
                    if (mark_decision_l4s == true){
                        hdr.ipv4.ecn = 3;
                    } 
                }
                // ========== TRÁFEGO CLASSIC: DROP PROBABILÍSTICO ==========
                else {
                    bool drop_decision_classic;
                    dropProbability.read(dropProb, (bit<32>)standard_metadata.egress_port);

                    // Decisão probabilística de drop
                    if (rand_classic < dropProb){
                        dropProb_temp = dropProb - 1;
                        dropProbability.write((bit<32>)standard_metadata.egress_port, dropProb_temp);
                        drop_decision_classic = true;
                    } else {
                        dropProb_temp = dropProb + 1;
                        dropProbability.write((bit<32>)standard_metadata.egress_port, dropProb_temp);
                        drop_decision_classic = false;
                    }

                    // Dropar pacote via clonagem + recirculação
                    if (drop_decision_classic == true){
                        meta.queue_metadata.output_port = (bit<32>)standard_metadata.egress_port;
                        clonePacket();
                    }
                }
            }
            // ========== CONGESTIONAMENTO SEVERO ==========
            else if (target_violation == 2){
                // L4S: marca sempre
                if (hdr.ipv4.l4s == 1){
                    hdr.ipv4.ecn = 3;
                }
                // Classic: dropa sempre
                else {
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
        packet.emit(hdr.tcp);
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