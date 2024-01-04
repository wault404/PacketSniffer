import time
from Analyzer import PacketSniffer

def repeat_capture(target_ip, num_repeats=15):
    for i in range(1, num_repeats + 1):
        packet_sniffer = PacketSniffer(target_ip)
        try:
            packet_sniffer.start_capture()
        except KeyboardInterrupt:
            pass
        time.sleep(30)

if __name__ == "__main__":
    target_ip = "192.168.0.108"
    num_repeats = 15
    while True:
        repeat_capture(target_ip, num_repeats)