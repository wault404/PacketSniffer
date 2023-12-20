from scapy.all import sniff, conf
from scapy.layers.inet import IP
import geoip2.database
from ipwhois import IPWhois
import tkinter as tk
from tkinter import ttk
from datetime import datetime, timedelta

conf.use_pcap = True

class PacketSniffer:
    def __init__(self, target_ip, capture_duration_minutes=1):
        self.target_ip = target_ip
        self.capture_duration = timedelta(minutes=capture_duration_minutes)
        self.start_time = datetime.now()
        self.reader = geoip2.database.Reader(r'C:\Users\Wault404\Desktop\python\SOCAnalyze\GeoLite2-City_20231110\GeoLite2-City.mmdb')
        self.geoip_results = {}

    def packet_callback(self, packet):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_size = len(packet)

        try:
            response = self.reader.city(src_ip)
            country = response.country.name
            city = response.city.name

            ipwhois = IPWhois(src_ip)
            result = ipwhois.lookup_rdap()
            as_info = result.get('asn_description', 'N/A')

            geoip_info = f"Country: {country}, City: {city}"
        except geoip2.errors.AddressNotFoundError:
            geoip_info = "GeoIP information not available"
            as_info = "N/A"
        except Exception as e:
            geoip_info = f"Error retrieving GeoIP information: {e}"
            as_info = "N/A"

        if as_info == "arin-pfs-sea":
            as_info = "Custom AS Organization: arin-pfs-sea"

        key = (src_ip, dst_ip)

        if key in self.geoip_results:
            self.geoip_results[key]['Packet Size'] += packet_size
            self.geoip_results[key]['Number of Packets'] += 1
        else:
            self.geoip_results[key] = {
                'Source IP': src_ip,
                'Destination IP': dst_ip,
                'Packet Size': packet_size,
                'GeoIP Information': geoip_info,
                'AS Organization': as_info,
                'Number of Packets': 1
            }

        elapsed_time = datetime.now() - self.start_time
        if elapsed_time >= self.capture_duration:
            self.stop_capture()

    def start_capture(self):
        try:
            sniff(prn=self.packet_callback, filter=f"host {self.target_ip}", store=0)
        except KeyboardInterrupt:
            self.stop_capture()

    def stop_capture(self):
        print("\nStopping capture...")
        self.reader.close()
        self.display_geoip_table()

    def display_geoip_table(self):
        root = tk.Tk()
        root.title("GeoIP Information")

        tree = ttk.Treeview(root)
        tree["columns"] = ("Source IP", "Destination IP", "Packet Size", "Number of Packets", "GeoIP Information", "AS Organization")
        for col in tree["columns"]:
            tree.heading(col, text=col)
        tree.pack(expand=True, fill=tk.BOTH)

        for idx, (key, result) in enumerate(self.geoip_results.items()):
            tree.insert("", idx, values=(
                result['Source IP'],
                result['Destination IP'],
                result['Packet Size'],
                result['Number of Packets'],
                result['GeoIP Information'],
                result['AS Organization']
            ))

        tree.mainloop()

if __name__ == "__main__":
    target_ip = "192.168.0.103"
    packet_sniffer = PacketSniffer(target_ip)
    packet_sniffer.start_capture()
