from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.config import conf
import socket
import geoip2.database

conf.use_pcap = True

class PacketSniffer:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.reader = geoip2.database.Reader(r'C:\Users\Wault404\Desktop\python\SOCAnalyze\GeoLite2-City_20231110\GeoLite2-City.mmdb')
    def resolve_ip_name(self, ip_address):
        try:
            host_name, _, _ = socket.gethostbyaddr(ip_address)
            return host_name
        except socket.herror:
            return "N/A"

    def packet_callback(self, packet):
        packet_summary = f"Summary: {packet.summary()}"

        src_name = self.resolve_ip_name(packet[IP].src)
        dst_name = self.resolve_ip_name(packet[IP].dst)
        packet_summary += f"\nSource IP: {packet[IP].src} ({src_name}), Destination IP: {packet[IP].dst} ({dst_name})"


        packet_summary += f"\nPacket Size: {len(packet)} bytes"

        geoip_info = self.get_geoip_info(packet[IP].src)
        packet_summary += f"\nGeoIP: {geoip_info}"

        print(packet_summary)

    def get_geoip_info(self, ip_address):
        try:
            response = self.reader.city(ip_address)
            country = response.country.name
            city = response.city.name
            return f"Country: {country}, City: {city}"
        except geoip2.errors.AddressNotFoundError:
            return "GeoIP information not available"
        except Exception as e:
            return f"Error retrieving GeoIP information: {e}"

    def start_capture(self):
        try:
            sniff(prn=self.packet_callback, filter=f"host {self.target_ip}", store=0)
        except KeyboardInterrupt:
            print("\nExiting...")

    def on_stop(self):
        self.reader.close()


if __name__ == "__main__":
    target_ip = "TvojIPsem"
    packet_sniffer = PacketSniffer(target_ip)
    packet_sniffer.start_capture()
