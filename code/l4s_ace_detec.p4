/* -*- P4_16 -*- */

#include <core.p4>
#include <v1model.p4>

#define PORTS 10
#define MAX_FLOWS 256  

// Recirculation packet capture interval time
#define SAMPLE_INTERVAL_US 10
// Strike limits for blacklist insertion
#define MAX_STRIKES 1000
// Verification window after congestion detected
#define VERIFICATION_WINDOW_US 10000000000

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

header tcp_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;    // ECN/ACE bits no TCP
    bit<6>  ctrl;   // Flags de controle (ACK é o 2º bit da esquerda)
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

parser MyParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start { transition parse_ethernet; }
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) { TYPE_IPV4: parse_ipv4; default: accept; }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){ PROTO_TCP: parse_tcp; default: accept; }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}   

control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply { } }

/*************************************************************************
************** I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    register<bit<1>>(PORTS) flagtoDrop_reg;
    counter(4, CounterType.packets) forwardingPkt;
    counter(4, CounterType.packets) dropPkt;
    counter(4, CounterType.packets) dropRecirc;

    // ========== Registers for attack detection ==========
    // Armazena se um fluxo (hash) foi marcado com CE recentemente
    register<bit<1>>(MAX_FLOWS) reg_congested_flows; 
    // Armazena fluxos bloqueados (maliciosos)
    register<bit<1>>(MAX_FLOWS) reg_blocked_flows;
    // Contador de strikes/infrações por fluxo
    register<bit<32>>(MAX_FLOWS) reg_strikes_counter;
    
    // ========== Temporal verification window ==========
    // Flag global que indica se estamos dentro da janela de verificação
    register<bit<1>>(1) reg_verification_window_active;
    // Timestamp de quando a janela foi ativada
    register<bit<48>>(1) reg_verification_window_start;

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
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { ipv4_forward; drop_regular; NoAction; }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.tcp.isValid()) {
            // Calcular Hash do Fluxo Atual (Direto)
            bit<32> current_flow_hash;
            hash(current_flow_hash, HashAlgorithm.crc32, (bit<32>)0,
                {hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.tcp.srcPort, hdr.tcp.dstPort, hdr.ipv4.protocol},
                (bit<32>)MAX_FLOWS);

            // 1. VERIFICAÇÃO DE LISTA NEGRA (Mitigação)
            bit<1> is_blocked;
            reg_blocked_flows.read(is_blocked, current_flow_hash);
            if (is_blocked == 1) {
                mark_to_drop(standard_metadata); // Dropa pacote do atacante
                return; // Encerra processamento para este pacote
            }

            // 2. PROCESSAMENTO DE PACOTES RECIRCULADOS (Ativação da Janela)
            if (standard_metadata.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_RECIRC) {
                // Se detectou ECN=3, ATIVA a janela de verificação
                if (hdr.ipv4.ecn == 3) {
                    // Registra que este fluxo sofreu congestionamento
                    reg_congested_flows.write(current_flow_hash, 1);
                    
                    // ========== ATIVAR JANELA DE VERIFICAÇÃO ==========
                    reg_verification_window_active.write(0, 1);
                    // Salva o timestamp de quando a janela foi ativada
                    reg_verification_window_start.write(0, standard_metadata.ingress_global_timestamp);
                    // ==================================================
                    mark_to_drop(standard_metadata); 
                    return;
                }

            }

            // ========== VERIFICAÇÃO DE ACKs APENAS DENTRO DA JANELA ==========
            bit<1> window_active;
            reg_verification_window_active.read(window_active, 0);
            
            // Só processa ACKs se a janela estiver ATIVA
            if (window_active == 1) {
                // Verificar se a janela ainda está válida (não expirou)
                bit<48> window_start;
                reg_verification_window_start.read(window_start, 0);
                bit<48> current_time = standard_metadata.ingress_global_timestamp;
                bit<48> elapsed_time = current_time - window_start;
                
                // Se passou o tempo DESATIVA a janela
                if (elapsed_time >= VERIFICATION_WINDOW_US) {
                    reg_verification_window_active.write(0, 0);
                    // Não precisa limpar reg_congested_flows - será sobrescrito naturalmente
                } 
                // Janela ainda ativa: VERIFICA ACKs
                else {
                    // Verifica se é um ACK (bit 4 = 0x10)
                    if ((hdr.tcp.ctrl & 0x10) != 0) {
                        
                        // Calcular Hash Reverso (fluxo original)
                        bit<32> reverse_hash;
                        hash(reverse_hash, HashAlgorithm.crc32, (bit<32>)0,
                            {hdr.ipv4.dstAddr, hdr.ipv4.srcAddr, hdr.tcp.dstPort, hdr.tcp.srcPort, hdr.ipv4.protocol},
                            (bit<32>)MAX_FLOWS);

                        bit<1> was_congested;
                        reg_congested_flows.read(was_congested, reverse_hash);

                        // Se o fluxo original foi marcado com CE
                        if (was_congested == 1) {
                            bit<32> current_strikes;
                            reg_strikes_counter.read(current_strikes, reverse_hash);
                            
                            // Verifica se o ACK sinaliza ACE (hdr.tcp.ecn > 0)
                            // Se hdr.tcp.ecn == 0, o usuário está IGNORANDO o congestionamento
                            if (hdr.tcp.ecn == 0) {
                                // ATAQUE DETECTADO: Incrementa strikes
                                current_strikes = current_strikes + 1;
                                reg_strikes_counter.write(reverse_hash, current_strikes);
                                
                                // Se atingiu o limite, BLOQUEIA o fluxo
                                if (current_strikes >= MAX_STRIKES) {
                                    reg_blocked_flows.write(reverse_hash, 1);
                                    // Opcional: Limpa strikes após bloqueio
                                    #reg_strikes_counter.write(reverse_hash, 0);
                                }
                            } else {
                                // COMPORTAMENTO Benigno: ACK sinalizou ECE
                                // Reseta strikes (comportamento benigno)
                                if (current_strikes > 0) {
                                    reg_strikes_counter.write(reverse_hash, 0);
                                }
                                // Limpa marcação de congestionamento (já respondeu)
                                reg_congested_flows.write(reverse_hash, 0);
                            }
                        }
                    }
                }
            }
            // ============================================================================
        }

        // Lógica original de Recirculação de pacotes Classic (BMv2 default) e Roteamento
        if (standard_metadata.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_RECIRC) {
            flagtoDrop_reg.write(meta.queue_metadata.output_port, 1);
            drop_recirc();
        }
        else {
            ipv4_lpm.apply();
            if (hdr.ipv4.isValid()) {
                if (hdr.ipv4.l4s == 1) {
                    standard_metadata.priority = 7;
                } else {
                    standard_metadata.priority = 0;
                }
            }
            
            // Controle de Congestionamento (Original)
            bit<1> flag;
            flagtoDrop_reg.read(flag, (bit<32>)standard_metadata.egress_spec);
            if (flag == 1){            
                if (hdr.ipv4.l4s != 1){
                    standard_metadata.priority = (bit<3>)0;
                    flagtoDrop_reg.write((bit<32>)standard_metadata.egress_spec, 0);
                    drop_regular();
                }
                if (hdr.ipv4.l4s == 1){
                    standard_metadata.priority = (bit<3>)7;
                }     
            }
        }
    }
}

/*************************************************************************
**************** E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    register<bit<32>>(8) QueueID;
    register<bit<16>>(PORTS) dropProbability;
    register<bit<32>>(PORTS) QDelay_reg;
    register<bit<32>>(2) queue_ewma_classic;
    register<bit<32>>(2) queue_ewma_l4s;
    
    // Timer para amostragem (1 registro global ou por porta, aqui usando 1 global índice 0)
    register<bit<48>>(1) reg_sampling_timer;

    counter(4, CounterType.packets) recirc;
    counter(4, CounterType.packets) cloneCount;
    counter(PORTS, CounterType.packets) ecnMarkedPkt;

    action recirculate_packet(){
        recirculate_preserving_field_list(0);
        recirc.count(meta.queue_metadata.output_port);
    }

    action clonePacket(){
        clone_preserving_field_list(CloneType.E2E, meta.queue_metadata.output_port, 0);
        cloneCount.count(meta.queue_metadata.output_port);
    }
    
    apply {
        QueueID.write((bit<32>)standard_metadata.qid, 1);
        
        if (standard_metadata.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE) {
            meta.queue_metadata.output_port = (bit<32>)standard_metadata.egress_port;
            recirculate_packet();
        } 
        else { 
            bit<32> TARGET_DELAY = 20000;
            bit<32> qdelay = (bit<32>)standard_metadata.deq_timedelta;
            bit<32> previousQDelay;
            QDelay_reg.read(previousQDelay, (bit<32>)standard_metadata.egress_port);
            
            bit<32> EWMA = (qdelay>>1) + (previousQDelay>>1);
            QDelay_reg.write((bit<32>)standard_metadata.egress_port, EWMA);
            
            if (standard_metadata.egress_port == 3) {
                if (standard_metadata.qid == 0) {
                    queue_ewma_classic.write(0, EWMA);
                } else if (standard_metadata.qid == 7) {
                    queue_ewma_l4s.write(0, EWMA);
                }
            }
                                 
            bit<8> target_violation = 0;
            if (EWMA <= TARGET_DELAY){ target_violation = 0; }
            else if ((EWMA > TARGET_DELAY) && (EWMA < (TARGET_DELAY<<1))){ target_violation = 1; }
            else if (EWMA >= (TARGET_DELAY<<1)){ target_violation = 2; } 

            if (target_violation == 1) {
                bit<16> rand_classic;
                random(rand_classic, 0, 65535);
                bit<16> rand_l4s = rand_classic >> 1;
                bit<16> dropProb;
                bit<16> dropProb_temp;

                // L4S: MARCAÇÃO ECN
                if (hdr.ipv4.l4s == 1){
                    bool mark_decision_l4s;
                    dropProbability.read(dropProb, (bit<32>)standard_metadata.egress_port);
                    
                    if (rand_l4s < dropProb){
                        dropProb_temp = dropProb - 1;
                        dropProbability.write((bit<32>)standard_metadata.egress_port, dropProb_temp);
                        mark_decision_l4s = true;
                    } else {
                        dropProb_temp = dropProb + 1;
                        dropProbability.write((bit<32>)standard_metadata.egress_port, dropProb_temp);
                        mark_decision_l4s = false;
                    }

                    if (mark_decision_l4s == true){
                        hdr.ipv4.ecn = 3;
                        ecnMarkedPkt.count((bit<32>)standard_metadata.egress_port);

                        // === CLONAGEM PARA Ativar gatilho do Egress ===
                        bit<48> last_sample_ts;
                        bit<48> now = standard_metadata.egress_global_timestamp;
                        reg_sampling_timer.read(last_sample_ts, 0);
                        
                        // Amostragem: clonar apenas a cada SAMPLE_INTERVAL_US
                        if ((now - last_sample_ts) >= SAMPLE_INTERVAL_US) {
                            reg_sampling_timer.write(0, now);
                            // Clona pacote para Ingress (original continua para destino)
                            clonePacket();
                        }
                        // ==========================================================
                    } 
                }
                // Classic: DROP (Original)
                else {
                    bool drop_decision_classic;
                    dropProbability.read(dropProb, (bit<32>)standard_metadata.egress_port);
                    if (rand_classic < dropProb){
                        dropProb_temp = dropProb - 1;
                        dropProbability.write((bit<32>)standard_metadata.egress_port, dropProb_temp);
                        drop_decision_classic = true;
                    } else {
                        dropProb_temp = dropProb + 1;
                        dropProbability.write((bit<32>)standard_metadata.egress_port, dropProb_temp);
                        drop_decision_classic = false;
                    }
                    if (drop_decision_classic == true){
                        meta.queue_metadata.output_port = (bit<32>)standard_metadata.egress_port;
                        clonePacket();
                    }
                }
            }
            // CONGESTIONAMENTO SEVERO
            else if (target_violation == 2){
                if (hdr.ipv4.l4s == 1){
                    hdr.ipv4.ecn = 3;
                    ecnMarkedPkt.count((bit<32>)standard_metadata.egress_port);
                    
                    // === CLONAGEM PARA DETECÇÃO (congestionamento severo) ===
                    bit<48> last_sample_ts;
                    bit<48> now = standard_metadata.egress_global_timestamp;
                    reg_sampling_timer.read(last_sample_ts, 0);
                    
                    if ((now - last_sample_ts) >= SAMPLE_INTERVAL_US) {
                        reg_sampling_timer.write(0, now);
                        // E2E clone (Egress → volta para Ingress)
                        clonePacket();
                    }
                    // ========================================================
                }
                else {
                    meta.queue_metadata.output_port = (bit<32>)standard_metadata.egress_port;
                    clonePacket();
                }
            }
        }             
    } 
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.l4s, hdr.ipv4.ecn,
              hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset,
              hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
