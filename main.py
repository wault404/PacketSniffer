# ScriptForCapturing
from scapy.all import sniff
from scapy.layers.inet import IP
import socket
# AndroidAppScript
import kivy
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.clock import Clock
from kivy.uix.textinput import TextInput



class MyRoot(BoxLayout):
    def __init__(self, **kwargs):
        super(MyRoot, self).__init__(**kwargs)

        self.orientation = 'vertical'
        self.packets = []  # List to store packets
        self.packet_textinput = TextInput(text="-", font_size=12, readonly=True)
        self.add_widget(self.packet_textinput)

        Clock.schedule_interval(self.update_packet_info, 0.1)
        self.local_ip = get_local_ip_address()

    def update_packet_info(self, dt):
        self.capture_network_packets()

    def capture_network_packets(self):
        try:
            sniff(prn=lambda pkt: self.packet_callback(pkt, self.local_ip), store=0, timeout=0.5)
        except KeyboardInterrupt:
            print("\nExiting...")

        # Append new packets to the list
        self.packet_textinput.text = "\n".join(self.packets)

    def packet_callback(self, packet, local_ip):
        if IP in packet and (packet[IP].src == local_ip or packet[IP].dst == local_ip):
            self.packets.append(packet.summary())
            print(packet.summary())

    def start_capture(self, instance):
        # Clear the existing content
        self.packets = []
        self.packet_textinput.text = ""
        self.capture_network_packets()
def get_local_ip_address():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except socket.error:
        return None

class PacketSnifferApp(App):
    def build(self):
        return MyRoot()

if __name__ == "__main__":
    PacketSnifferApp().run()
