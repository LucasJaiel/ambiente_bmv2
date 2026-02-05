#!/bin/bash

# Definição das variáveis
SERVER_IP="192.168.57.20"
DURATION=180
INTERVAL=1

echo "Iniciando teste iperf para $SERVER_IP..."
echo "Duração: $DURATION segundos"
echo "Intervalo de reporte: $INTERVAL segundo"
echo "----------------------------------------"

iperf -c $SERVER_IP -t $DURATION -i $INTERVAL

echo "----------------------------------------"
echo "Teste finalizado."