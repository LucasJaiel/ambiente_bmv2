#!/usr/bin/env python3

#Jogar no path python onde está o bm_runtime
import sys
sys.path.insert(0, '/usr/local/lib/python3.8/site-packages')
import csv
import time
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
#Adição do protocolo multiplexado para estebelcer conexão com servidor Thrfit
from thrift.protocol import TMultiplexedProtocol
# Thrift BMv2
from bm_runtime.standard import Standard
from bm_runtime.standard.ttypes import *

# ==========================
# CONFIGURAÇÕES
# ==========================
SWITCH_IP = "192.168.63.2"
THRIFT_PORT = 9090
CTX_ID = 0

CSV_FILE = "a3_2metrics_stream.csv"
INTERVAL = 1  # segundos

# Registradores / contadores
REG_QUEUE_EWMA_L4S = "MyEgress.queue_ewma_l4s"
REG_QUEUE_EWMA_CLASSIC = "MyEgress.queue_ewma_classic"
CNT_ECN_MARKED = "MyEgress.ecnMarkedPkt"
CNT_DROP_PKT = "MyIngress.dropPkt"

IDX_QUEUE = 0
IDX_PORT = 3

# ==========================
# CONEXÃO THRIFT
# ==========================
def thrift_connect():
    transport = TSocket.TSocket(SWITCH_IP, THRIFT_PORT)
    transport = TTransport.TBufferedTransport(transport)

    base_protocol = TBinaryProtocol.TBinaryProtocol(transport)
    protocol = TMultiplexedProtocol.TMultiplexedProtocol(
        base_protocol, "standard"
    )

    client = Standard.Client(protocol)
    transport.open()
    return transport, client

# ==========================
# LEITURA DAS MÉTRICAS
# ==========================
def read_metrics(client):
    ewma_l4s = client.bm_register_read(
        CTX_ID, REG_QUEUE_EWMA_L4S, IDX_QUEUE
    )

    ewma_classic = client.bm_register_read(
        CTX_ID, REG_QUEUE_EWMA_CLASSIC, IDX_QUEUE
    )

    ecn_marked = client.bm_counter_read(
        CTX_ID, CNT_ECN_MARKED, IDX_PORT
    ).packets

    drop_pkt = client.bm_counter_read(
        CTX_ID, CNT_DROP_PKT, IDX_PORT
    ).packets

    return ewma_l4s, ewma_classic, ecn_marked, drop_pkt

# ==========================
# MAIN
# ==========================
def main():
    transport, client = thrift_connect()

    with open(CSV_FILE, mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp",
            "queue_ewma_l4s",
            "queue_ewma_classic",
            "ecn_marked_pkt",
            "drop_pkt"
        ])

        print("[INFO] Coletando métricas... Ctrl+C para sair")

        try:
            while True:
                ts = time.time()
                ewma_l4s, ewma_classic, ecn, drop = read_metrics(client)

                writer.writerow([
                    ts, ewma_l4s, ewma_classic, ecn, drop
                ])
                f.flush()

                print(f"[{ts:.3f}] L4S={ewma_l4s} CLASSIC={ewma_classic} ECN={ecn} DROP={drop}")

                time.sleep(INTERVAL)

        except KeyboardInterrupt:
            print("\n[INFO] Encerrando coleta")

    transport.close()

if __name__ == "__main__":
    main()
