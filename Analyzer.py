from scapy.all import sniff, conf
from scapy.layers.inet import IP
import geoip2.database
from ipwhois import IPWhois
import tkinter as tk
from tkinter import ttk
from datetime import datetime, timedelta
import csv
import time
# POSSIBLE LOOKUP BATCHING FOR BETTER OPTIMIZATION GEOIP2-City SUPPORTS IT!
conf.use_pcap = True

class PacketSniffer:
    def __init__(self, target_ip, capture_duration_minutes=5):
        self.target_ip = target_ip
        self.capture_duration = timedelta(minutes=capture_duration_minutes)
        self.start_time = time.time()
        self.geoip_results = []
        self.reader = geoip2.database.Reader(r'C:\Users\Wault404\Desktop\python\SOCAnalyze\GeoLite2-City_20231110\GeoLite2-City.mmdb')

        # Cache for storing GeoIP information
        self.geoip_cache = {}

    def get_geoip_info_from_cache(self, src_ip):
        return self.geoip_cache.get(src_ip)

    def add_geoip_info_to_cache(self, src_ip, geoip_info):
        self.geoip_cache[src_ip] = geoip_info

    def packet_callback(self, packet):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_size = len(packet)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cached_result = self.get_geoip_info_from_cache(src_ip)
        if cached_result:
            geoip_info, as_info = cached_result
        else:
            geoip_info, as_info = self.fetch_geoip_info(src_ip)
            self.add_geoip_info_to_cache(src_ip, (geoip_info, as_info))

        self.geoip_results.append({
            'Timestamp': timestamp,
            'Source IP': src_ip,
            'Destination IP': dst_ip,
            'Packet Size': packet_size,
            'GeoIP Information': geoip_info,
            'AS Organization': as_info
        })

    def timeout_callback(self, packet):
        elapsed_time = datetime.now() - self.start_time
        if elapsed_time >= self.capture_duration:
            return True
    def fetch_geoip_info(self, src_ip):
        try:
            response = self.reader.city(src_ip)
            country = response.country.name
            city = response.city.name
            ipwhois = IPWhois(src_ip)
            ipwhois_result = ipwhois.lookup_rdap()
            as_info = ipwhois_result.get('asn_description', 'N/A')
            geoip_info = f"Country: {country}, City: {city}"

            return geoip_info, as_info
        except geoip2.errors.AddressNotFoundError:
            return "GeoIP information not available", "N/A"
        except Exception as e:
            return f"Error retrieving GeoIP information: {e}", "N/A"

    def start_capture(self):
        try:
            self.start_time = datetime.now()
            sniff(prn=self.packet_callback, filter=f"host {self.target_ip}", store=0, stop_filter=self.timeout_callback,
                  timeout=self.capture_duration.total_seconds())
        except KeyboardInterrupt:
            pass
        finally:
            self.stop_capture()

    def stop_capture(self):
        print("\nStopping capture...")
        self.reader.close()
        self.save_to_csv("geoip_information.csv", self.geoip_results)
        self.display_geoip_table()

    def save_to_csv(self, filename, data):
        with open(filename, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(
                ["Timestamp", "Source IP", "Destination IP", "Packet Size", "GeoIP Information", "AS Organization"])
            for result in data:
                writer.writerow([
                    result['Timestamp'],
                    result['Source IP'],
                    result['Destination IP'],
                    result['Packet Size'],
                    result['GeoIP Information'],
                    result['AS Organization']
                ])

    def display_geoip_table(self):
        root = tk.Tk()
        root.title("GeoIP Information")

        tree = ttk.Treeview(root)
        tree["columns"] = ("Timestamp", "Source IP", "Destination IP", "Packet Size", "GeoIP Information", "AS Organization")
        tree.heading("Timestamp", text="Timestamp")
        tree.heading("Source IP", text="Source IP")
        tree.heading("Destination IP", text="Destination IP")
        tree.heading("Packet Size", text="Packet Size")
        tree.heading("GeoIP Information", text="GeoIP Information")
        tree.heading("AS Organization", text="AS Organization")

        for idx, result in enumerate(self.geoip_results):
            tree.insert("", idx, values=(
                result['Timestamp'],
                result['Source IP'],
                result['Destination IP'],
                result['Packet Size'],
                result['GeoIP Information'],
                result['AS Organization']
            ))

        tree.pack(expand=True, fill=tk.BOTH)

        grouped_results = {}
        for result in self.geoip_results:
            as_org = result['AS Organization']
            if as_org not in grouped_results:
                grouped_results[as_org] = []
            grouped_results[as_org].append(result)

        grouped_root = tk.Tk()
        grouped_root.title("Grouped GeoIP Information")

        grouped_tree = ttk.Treeview(grouped_root)
        grouped_tree["columns"] = (
            "Timestamp", "Source IP", "Destination IP", "Packet Size (KB)", "GeoIP Information", "AS Organization")
        grouped_tree.heading("Timestamp", text="Timestamp")
        grouped_tree.heading("Source IP", text="Source IP")
        grouped_tree.heading("Destination IP", text="Destination IP")
        grouped_tree.heading("Packet Size (KB)", text="Packet Size (KB)")
        grouped_tree.heading("GeoIP Information", text="GeoIP Information")
        grouped_tree.heading("AS Organization", text="AS Organization")

        for as_org, packets in grouped_results.items():
            for idx, packet in enumerate(packets):
                packet_size_kb = packet['Packet Size'] / 1024.0
                grouped_tree.insert("", idx, values=(
                    packet['Timestamp'],
                    packet['Source IP'],
                    packet['Destination IP'],
                    f"{packet_size_kb:.2f} KB",
                    packet['GeoIP Information'],
                    packet['AS Organization']
                ))

        grouped_tree.pack(expand=True, fill=tk.BOTH)

        root.mainloop()
        grouped_root.mainloop()

if __name__ == "__main__":
    target_ip = "192.168.0.108"
    packet_sniffer = PacketSniffer(target_ip)
#target_ip IS USER DEPENDENT RUN ipconfig IN CMD AND EXTRACT THE IPv4 Addres
    try:
        packet_sniffer.start_capture()
    except KeyboardInterrupt:
        pass