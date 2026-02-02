This repository contains the artifacts used in the paper: When ECN Lies: Unfairness and Exploitation in L4S.
Low Latency, Low Loss and Scalable Throughput (L4S) is a recent IETF architecture that enables Internet applications to achieve ultra-low queuing latency and scalable throughput. However, the architecture faces critical security challenges, particularly the non-responsive ECN attack, where malicious flows exploit the low-latency queue by manipulating ECN headers.
<p align="center">
  <img src="img/ataque-wide.svg" alt="Enviroment" width="300"/>
</p>
This work presents:
A novel data-plane-based detection and mitigation mechanism implemented in P4.
P4-Based Defense Mechanism: Line-rate detection and mitigation without requiring end-host modifications.

Used Tools:
- VirtualBox >= 6.1
- Vagrant >= 2.2.0
- ansible [core 2.15.13]
- python 3.9.2 for some dependencies.  OBS: The P4 Compiler and BMV2 (Behavioral Model 2) are integrated into the box with the VM defined as "router_bmv2" in the Vagrantfile.

