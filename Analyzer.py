'Libraries used :'
'scapy : a python library used for network packet manipulation and capture'
'geoip2 : used with GeoLite2-City.mmdb to assign geographical info about IPs'
'ipwhois : used for the lookup of Autonomous Systems (AS) via IP'
'tkinter and ttk : display the captured packets in a grid layout'
'datetime : for handling capture_duration_minutes '
'csv : used for saving .csv files'
'tqdm : library for better progress visualization via an progression bar'

from scapy.all import sniff, conf
from scapy.layers.inet import IP
import geoip2.database
from ipwhois import IPWhois
import tkinter as tk
from tkinter import ttk
from datetime import datetime, timedelta
import csv
from tqdm import tqdm

#POSSIBLE LOOKUP BATCHING FOR geoip2 lib
conf.use_pcap = True

'Initialization : capture_duration_minutes can be adjusted by user preference'
'target_ip : used to filter captured packets via an IP'
'capture_duration_minutes : the capture time variable - determines for how long will the capture keep running'
'start_time : variable for storing the start time of the capture'
'geoip_results : list used for storing detail about each packet'
'geoip_cache : cache to avoid redundant GeoIP lookups'
'reader : starts the geoip2 reader with the path to .mmdb'

class PacketSniffer:
    def __init__(self, target_ip, capture_duration_minutes=1):
        #capture_duration_minutes is CHANGEABLE
        self.target_ip = target_ip
        self.capture_duration = timedelta(minutes=capture_duration_minutes)
        self.start_time = None
        self.geoip_results = []
        self.geoip_cache = {}
        self.reader = geoip2.database.Reader(r'C:\Users\Wault404\Desktop\python\SOCAnalyze\GeoLite2-City_20231110\GeoLite2-City.mmdb')

    'Packet_callback :'
    'Executed for each packet captured by Scapy'
    'extracts destination IP, packet size in bytes, and timestamp' \
    'result saved into geoip_results'
    def packet_callback(self, packet):
            try:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                packet_size = len(packet)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                self.geoip_results.append({
                    'Timestamp': timestamp,
                    'Source IP': src_ip,
                    'Destination IP': dst_ip,
                    'Packet Size': packet_size,
                    'GeoIP Information': None,
                    'AS Organization': None
                })
            except Exception as e:
                print(f"Error in packet_callback: {e}")

    'timeout_callback : stops the capture in case of a timer end'
    def timeout_callback(self, packet):
        elapsed_time = datetime.now() - self.start_time
        if elapsed_time >= self.capture_duration:
            return True

    'get_geoip_info :'
    'using the ipwhois library looks up the information for a given IP address, with caching to avoid useless lookups'
    'in case of an ip that is not recognized handles the exception and prints out an error'

    def get_geoip_info(self, ip):
        if ip in self.geoip_cache:
            return self.geoip_cache[ip]

        try:
            response = self.reader.city(ip)
            country = response.country.name
            city = response.city.name

            ipwhois = IPWhois(ip)
            ipwhois_result = ipwhois.lookup_rdap()
            as_info = ipwhois_result.get('asn_description', 'N/A')

            geoip_info = f"Country: {country}, City: {city}"
        except geoip2.errors.AddressNotFoundError:
            geoip_info = "GeoIP information not available"
            as_info = "N/A"
        except Exception as e:
            geoip_info = f"Error retrieving GeoIP information: {e}"
            as_info = "N/A"

        if as_info == "arin-pfs-sea":
            as_info = "Custom AS Organization: arin-pfs-sea"

        result = {'GeoIP Information': geoip_info, 'AS Organization': as_info}
        self.geoip_cache[ip] = result
        return result

    'assign_geoip_info :'
    'assigns the geographical locations to IP adresses and AS organization accordingly'
    def assign_geoip_info(self):
        for result in tqdm(self.geoip_results, desc="Assigning GeoIP Info", unit=" packet"):
            src_ip = result['Source IP']
            dst_ip = result['Destination IP']

            src_geoip_info = self.get_geoip_info(src_ip)
            dst_geoip_info = self.get_geoip_info(dst_ip)

            result['GeoIP Information'] = dst_geoip_info['GeoIP Information']
            result['AS Organization'] = dst_geoip_info['AS Organization']

    'start_capture :'
    'starts the capture with a progression bar'
    'filters packets using target_ip'
    'after the timer runs out the capture is stopped by the timeout_callback'
    def start_capture(self):
        try:
            with tqdm(total=self.capture_duration.total_seconds(), desc="Capturing Packets", unit="sniff") as pbar:
                self.start_time = datetime.now()
                sniff(prn=lambda pkt: self.update_progress(pkt, pbar), filter=f"src host {self.target_ip}",
                      store=0, stop_filter=self.timeout_callback,
                      timeout=self.capture_duration.total_seconds())
        except Exception as e:
            print(f"Error in start_capture: {e}")
        finally:
            self.stop_capture()

    'update_progress : updates the tqdm bar for each packet captured'
    def update_progress(self, packet, pbar):
        pbar.update(1)
        self.packet_callback(packet)

    'stop_capture :'
    'called by start_capture after timer runs out,'
    'assigns geographical information about IPs using assign_geoip_info'
    'closes the geoip2 database reader with the reader.close()'
    'saves to csv using save_to_csv'
    'display the tables with captured packets'
    def stop_capture(self):
        print("\nStopping capture...")
        self.assign_geoip_info()
        self.reader.close()
        self.save_to_csv("geoip_information.csv", self.geoip_results)
        self.display_geoip_table()

    'save_to_csv'
    'saves the information into a .csv file'
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
    'display_geoip_table'
    'creates gui using tkinter library to display captured packets'
    'second table is created with the results grouped by AS organizations'
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

    'Main Execution :'
    'target_ip : set a ip4 address of the device that is running the script'
if __name__ == "__main__":
    target_ip = "192.168.0.108"
    packet_sniffer = PacketSniffer(target_ip)
    try:
        packet_sniffer.start_capture()
    except KeyboardInterrupt:
        pass
