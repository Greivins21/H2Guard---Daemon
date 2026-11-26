# NFQUEUE-Based HTTP/2 DoS Mitigation Prototype

## Project Overview

This project was developed as part of a cybersecurity research effort focused on detecting and mitigating **asymmetric HTTP/2 Denial-of-Service (DoS) attacks** using **NFQUEUE-based packet interception**.

The objective is to evaluate whether a lightweight host-level defense mechanism can identify malicious HTTP/2 traffic patterns and dynamically block attackers before they significantly degrade server performance.

The prototype combines:

* **nftables** for packet filtering and dynamic blocking.
* **NFQUEUE** for packet delivery to user space.
* A custom **C daemon** for behavioral analysis and mitigation decisions.

---

## HTTP/2 Background

HTTP/2 improves web performance by introducing a binary framing layer that supports:

* Stream multiplexing
* Header compression
* Stream prioritization
* Flow control

These features reduce latency and improve efficiency, but they can also be abused to create asymmetric denial-of-service attacks.

---

## Threat Model

### Multiplexed Asymmetric Workload Attacks (MAWD)

Attackers exploit HTTP/2 multiplexing to generate a disproportionately high processing cost on the server while consuming relatively few client-side resources.

### Rapid Reset Attacks

The HTTP/2 Rapid Reset attack (CVE-2023-44487) rapidly creates and cancels streams using `RST_STREAM` frames. This forces the server to repeatedly allocate and release resources, potentially exhausting CPU capacity and degrading service availability.

---

## Proposed Solution

The prototype uses NFQUEUE to intercept HTTPS packets before they reach the application.

The daemon analyzes packet metadata and flow behavior to identify patterns associated with HTTP/2 abuse. When repeated suspicious activity is detected, the source IP address is dynamically added to an `nftables` blocklist.

This approach allows mitigation without modifying the protected web application.

---

## LAB REQUIREMENTS
- Minimum three different computers in a network laboratory that will act as: 
    1. Web server (victim)
    2. Attacker
    3. Normal user

---

## Project Structure

```text
.
├── README.md
├── Makefile
├── server_setup.sh
└── source/
    ├── daemon/     # NFQUEUE detection daemon
    ├── docker/     # Docker-based attack infrastructure
    └── web/        # Static Nginx website used during testing
```

---

## Server Setup

Execute the setup script from the project root:

```bash
sudo ./server_setup.sh
```

The script installs all required dependencies, configures the web server, and prepares the NFQUEUE environment.

### Main Components Installed

* nginx
* nftables
* libnetfilter-queue-dev
* libnfnetlink-dev
* libmnl-dev
* build-essential
* libssl-dev
* tcpdump
* sysstat
* htop
* iftop
* nload
* net-tools
* iproute2
* curl
* wget

---

## Attacker Setup

The attack machines require docker or independant installations of:

### nghttp2 Tools

```bash
sudo apt install nghttp2-client
```

Provides:

* `h2load`
* `nghttp`

### Rapid Reset Client

Clone and build:

```bash
git clone https://github.com/secengjeff/rapidresetclient.git
```

The tool is used to emulate HTTP/2 Rapid Reset behavior.

---

## Reproducing the Experiments

The original experiments used multiple Docker containers distributed across several attacker virtual machines.

Before launching the containers, update the target IP addresses inside the Docker configuration files to match your environment.

### MAWD Experiment

Example attack:

```bash
h2load -n200000 -c500 -m500 https://<VICTIM_IP>/
```

Parameters:

* `-n` Total requests
* `-c` Concurrent clients
* `-m` Concurrent streams per connection

### Rapid Reset Experiment

Example attack:

```bash
rapidresetclient \
    -requests=20000 \
    -url=https://<VICTIM_IP>/ \
    -wait=5 \
    -delay=1 \
    -concurrency=100
```

Parameters:

* `-requests` Total requests generated
* `-wait` Worker startup delay
* `-delay` Delay between `HEADERS` and `RST_STREAM` frames (ms)
* `-concurrency` Number of concurrent workers

---

## Monitoring and Evaluation

The following tools can be used to evaluate mitigation effectiveness and monitor server behavior:

| Tool         | Purpose                    |
| ------------ | -------------------------- |
| htop         | CPU and memory monitoring  |
| iftop        | Network bandwidth usage    |
| nload        | Throughput visualization   |
| tcpdump      | Packet inspection          |
| sar / mpstat | CPU statistics             |
| nft          | Firewall rule verification |
| curl         | Functional testing         |
| wget         | Functional testing         |

Typical evaluation metrics include:

* CPU utilization
* Server idle percentage
* Request latency
* Availability of legitimate traffic
* Detection and blocking events

---

## Docker-Based Attack Deployment

The attack infrastructure is containerized to simplify experiment reproduction and to emulate distributed attack sources.

### Build the Attack Containers

```bash
docker compose build m
```

### Launch a Single MAWD Attacker

```bash
docker compose up multiplexed_attacker
```

### Launch Multiple MAWD Attackers

For example, to start five multiplexed attackers:

```bash
docker compose up --scale multiplexed_attacker=5 multiplexed_attacker
```

### Launch a Single Rapid Reset Attacker

```bash
docker compose up rapidreset_attacker
```

### Launch Multiple Rapid Reset Attackers

For example, to start five Rapid Reset attackers:

```bash
docker compose up --scale rapidreset_attacker=5 rapidreset_attacker
```

### Check Running Containers

```bash
docker ps
```
### Stop the Attack Infrastructure

```bash
docker compose down
```

### Experimental Configuration

The original experiments were conducted using multiple attacker virtual machines, each running several instances of either the `multiplexed_attacker` or `rapidreset_attacker` service. Before executing the experiments, update the victim server IP address in the corresponding Dockerfiles to match the target environment.


## Disclaimer

This project is a research prototype designed for experimental evaluation of HTTP/2 attack mitigation techniques. It has not been tested for production deployment and should be used only in controlled environments.
