import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import socket
import struct
import textwrap
import threading
import time
from datetime import datetime
import sys
import os
import ctypes

try:
    from scapy.all import sniff, wrpcap, rdpcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Scapy library not found. Some functionality will be limited.\nInstall with: pip install scapy")

class PacketSniffer:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple Packet Sniffer")
        self.root.geometry("1200x700")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Variables
        self.is_running = False
        self.captured_packets = []
        self.selected_interface = tk.StringVar()
        self.filter_text = tk.StringVar()
        self.protocol_filter = tk.StringVar(value="All")
        self.dark_mode = tk.BooleanVar(value=False)
        
        # Main frame
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create the GUI elements
        self.create_menu()
        self.create_control_panel()
        self.create_packet_list()
        self.create_packet_details()
        self.create_status_bar()
        
        # Get available interfaces
        self.get_interfaces()
        
        # Apply initial theme
        self.toggle_theme()

    def create_menu(self):
        # Create menu bar
        menu_bar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menu_bar, tearoff=0)
        file_menu.add_command(label="Save Capture", command=self.save_capture)
        file_menu.add_command(label="Load Capture", command=self.load_capture)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)
        menu_bar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menu_bar, tearoff=0)
        view_menu.add_checkbutton(label="Dark Mode", variable=self.dark_mode, command=self.toggle_theme)
        menu_bar.add_cascade(label="View", menu=view_menu)
        
        # Help menu
        help_menu = tk.Menu(menu_bar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menu_bar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menu_bar)

    def create_control_panel(self):
        control_frame = ttk.LabelFrame(self.main_frame, text="Controls")
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Interface selection
        ttk.Label(control_frame, text="Interface:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.interface_combo = ttk.Combobox(control_frame, textvariable=self.selected_interface, state="readonly", width=30)
        self.interface_combo.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        # Start/Stop button
        self.start_btn = ttk.Button(control_frame, text="Start Capture", command=self.toggle_capture)
        self.start_btn.grid(row=0, column=2, padx=5, pady=5)
        
        # Clear button
        ttk.Button(control_frame, text="Clear", command=self.clear_packets).grid(row=0, column=3, padx=5, pady=5)
        
        # Filter section
        ttk.Label(control_frame, text="Filter:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        ttk.Entry(control_frame, textvariable=self.filter_text, width=30).grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Button(control_frame, text="Apply Filter", command=self.apply_filter).grid(row=1, column=2, padx=5, pady=5)
        
        # Protocol filter
        ttk.Label(control_frame, text="Protocol:").grid(row=1, column=3, padx=5, pady=5, sticky=tk.W)
        protocol_combo = ttk.Combobox(control_frame, textvariable=self.protocol_filter, state="readonly", width=10,
                                     values=["All", "TCP", "UDP", "ICMP", "ARP", "HTTP", "DNS"])
        protocol_combo.grid(row=1, column=4, padx=5, pady=5, sticky=tk.W)
        protocol_combo.bind("<<ComboboxSelected>>", lambda e: self.apply_filter())

    def create_packet_list(self):
        # Frame for packet list
        list_frame = ttk.LabelFrame(self.main_frame, text="Captured Packets")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create treeview for packets
        columns = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        self.packet_tree = ttk.Treeview(list_frame, columns=columns, show="headings")
        
        # Set column headings
        for col in columns:
            self.packet_tree.heading(col, text=col)
            if col == "Info":
                self.packet_tree.column(col, width=300)  # Info column wider
            elif col == "No.":
                self.packet_tree.column(col, width=50, anchor=tk.CENTER)  # Number column narrower
            elif col == "Length":
                self.packet_tree.column(col, width=60, anchor=tk.CENTER)  # Length column narrower
            else:
                self.packet_tree.column(col, width=120)
        
        # Create scrollbars
        y_scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        x_scrollbar = ttk.Scrollbar(list_frame, orient=tk.HORIZONTAL, command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=y_scrollbar.set, xscrollcommand=x_scrollbar.set)
        
        # Pack scrollbars and treeview
        y_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        x_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        self.packet_tree.pack(fill=tk.BOTH, expand=True)
        
        # Bind selection event
        self.packet_tree.bind("<<TreeviewSelect>>", self.on_packet_select)

    def create_packet_details(self):
        details_frame = ttk.LabelFrame(self.main_frame, text="Packet Details")
        details_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Text widget for packet details
        self.detail_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD, height=10)
        self.detail_text.pack(fill=tk.BOTH, expand=True)
        self.detail_text.config(state=tk.DISABLED)

    def create_status_bar(self):
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def get_interfaces(self):
        """Get network interfaces based on the platform"""
        interfaces = []
        
        if SCAPY_AVAILABLE:
            from scapy.arch import get_if_list
            interfaces = get_if_list()
        else:
            # Fallback method if Scapy is not available
            if sys.platform.startswith('win'):
                # On Windows
                interfaces = ["Ethernet", "Wi-Fi"]  # Simplified for this example
            elif sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
                # On Linux or MacOS
                interfaces = [iface for iface in os.listdir('/sys/class/net/') if iface != 'lo']
        
        if not interfaces:
            interfaces = ["Default"]
        
        self.interface_combo['values'] = interfaces
        self.interface_combo.current(0)

    def toggle_capture(self):
        if not self.is_running:
            # Start capture
            self.is_running = True
            self.start_btn.config(text="Stop Capture")
            
            # Start capture in a separate thread
            self.capture_thread = threading.Thread(target=self.start_capture)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            
            self.status_bar.config(text="Capturing packets...")
        else:
            # Stop capture
            self.is_running = False
            self.start_btn.config(text="Start Capture")
            self.status_bar.config(text="Capture stopped")

    def start_capture(self):
        """Start capturing packets using scapy or socket"""
        if SCAPY_AVAILABLE:
            self.capture_with_scapy()
        else:
            self.capture_with_socket()

    def capture_with_scapy(self):
        """Capture packets using scapy library"""
        interface = self.selected_interface.get()
        
        def packet_callback(packet):
            if not self.is_running:
                return
            
            # Extract packet information
            timestamp = datetime.fromtimestamp(packet.time).strftime('%H:%M:%S.%f')[:-3]
            
            # Try to get source and destination
            src = ""
            dst = ""
            proto = ""
            length = len(packet)
            info = ""
            
            # Layer 2
            if packet.haslayer('Ether'):
                src = packet.getlayer('Ether').src
                dst = packet.getlayer('Ether').dst
                proto = "Ethernet"
            
            # ARP
            if packet.haslayer('ARP'):
                src = packet.getlayer('ARP').psrc
                dst = packet.getlayer('ARP').pdst
                proto = "ARP"
                info = f"Who has {dst}? Tell {src}" if packet.getlayer('ARP').op == 1 else f"{src} is at {packet.getlayer('ARP').hwsrc}"
            
            # IPv4
            if packet.haslayer('IP'):
                src = packet.getlayer('IP').src
                dst = packet.getlayer('IP').dst
                
            # TCP/UDP/ICMP
            if packet.haslayer('TCP'):
                proto = "TCP"
                sport = packet.getlayer('TCP').sport
                dport = packet.getlayer('TCP').dport
                info = f"{src}:{sport} → {dst}:{dport}"
                
                # HTTP detection (simplified)
                if sport == 80 or dport == 80:
                    proto = "HTTP"
                # HTTPS detection
                elif sport == 443 or dport == 443:
                    proto = "HTTPS"
                    
                # Add flags info
                flags = packet.getlayer('TCP').flags
                if flags:
                    info += f" [Flags: {flags}]"
                    
            elif packet.haslayer('UDP'):
                proto = "UDP"
                sport = packet.getlayer('UDP').sport
                dport = packet.getlayer('UDP').dport
                info = f"{src}:{sport} → {dst}:{dport}"
                
                # DNS detection
                if sport == 53 or dport == 53:
                    proto = "DNS"
                    if packet.haslayer('DNS'):
                        dns_info = []
                        if packet.getlayer('DNS').qr == 0:  # Query
                            for i in range(packet.getlayer('DNS').qdcount):
                                if packet.getlayer('DNS').qd:
                                    dns_info.append(f"Query: {packet.getlayer('DNS').qd.qname.decode('utf-8', errors='ignore').rstrip('.')}")
                        else:  # Response
                            dns_info.append(f"Response: {packet.getlayer('DNS').ancount} answers")
                        
                        if dns_info:
                            info += f" [{', '.join(dns_info)}]"
                
            elif packet.haslayer('ICMP'):
                proto = "ICMP"
                icmp_type = packet.getlayer('ICMP').type
                icmp_code = packet.getlayer('ICMP').code
                
                if icmp_type == 8:
                    info = "Echo (ping) request"
                elif icmp_type == 0:
                    info = "Echo (ping) reply"
                else:
                    info = f"Type: {icmp_type}, Code: {icmp_code}"
            
            # Create user-friendly packet object
            packet_info = {
                "number": len(self.captured_packets) + 1,
                "time": timestamp,
                "source": src,
                "destination": dst,
                "protocol": proto,
                "length": length,
                "info": info,
                "raw": packet
            }
            
            # Add to packet list and update GUI
            self.captured_packets.append(packet_info)
            self.root.after(0, lambda: self.add_packet_to_tree(packet_info))
        
        try:
            # Use Scapy's sniff function to capture packets
            sniff(iface=interface if interface != "Default" else None, 
                  prn=packet_callback, 
                  store=0,
                  stop_filter=lambda x: not self.is_running)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to start capture: {str(e)}"))
            self.root.after(0, self.toggle_capture)

    def capture_with_socket(self):
        """Fallback method using raw sockets when scapy is not available"""
        try:
            # Create a raw socket
            conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            
            # Bind to interface
            conn.bind(('0.0.0.0', 0))
            
            # Include IP headers
            conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # Enable promiscuous mode
            try:
                conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                windows_mode = True
            except AttributeError:
                windows_mode = False
            
            packet_id = 0
            
            # Receive packets
            while self.is_running:
                raw_data, addr = conn.recvfrom(65535)
                packet_id += 1
                
                timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
                
                # Extract IP header
                ip_header = raw_data[0:20]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                
                version_ihl = iph[0]
                ihl = version_ihl & 0xF
                iph_length = ihl * 4
                
                protocol = iph[6]
                s_addr = socket.inet_ntoa(iph[8])
                d_addr = socket.inet_ntoa(iph[9])
                
                # Determine protocol
                proto_name = "Unknown"
                info = ""
                
                if protocol == 1:  # ICMP
                    proto_name = "ICMP"
                    icmp_header = raw_data[iph_length:iph_length+8]
                    icmp_type, code, _, _ = struct.unpack('!BBHL', icmp_header)
                    
                    if icmp_type == 8:
                        info = "Echo (ping) request"
                    elif icmp_type == 0:
                        info = "Echo (ping) reply"
                    else:
                        info = f"Type: {icmp_type}, Code: {code}"
                        
                elif protocol == 6:  # TCP
                    proto_name = "TCP"
                    tcp_header = raw_data[iph_length:iph_length+20]
                    tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                    
                    source_port = tcph[0]
                    dest_port = tcph[1]
                    
                    # Special ports
                    if source_port == 80 or dest_port == 80:
                        proto_name = "HTTP"
                    elif source_port == 443 or dest_port == 443:
                        proto_name = "HTTPS"
                    
                    info = f"{s_addr}:{source_port} → {d_addr}:{dest_port}"
                    
                    # Add flags info
                    flags = tcph[5] & 0x3F
                    flag_str = []
                    if flags & 0x01: flag_str.append("FIN")
                    if flags & 0x02: flag_str.append("SYN")
                    if flags & 0x04: flag_str.append("RST")
                    if flags & 0x08: flag_str.append("PSH")
                    if flags & 0x10: flag_str.append("ACK")
                    if flags & 0x20: flag_str.append("URG")
                    
                    if flag_str:
                        info += f" [Flags: {', '.join(flag_str)}]"
                    
                elif protocol == 17:  # UDP
                    proto_name = "UDP"
                    udp_header = raw_data[iph_length:iph_length+8]
                    udph = struct.unpack('!HHHH', udp_header)
                    
                    source_port = udph[0]
                    dest_port = udph[1]
                    
                    # DNS detection
                    if source_port == 53 or dest_port == 53:
                        proto_name = "DNS"
                    
                    info = f"{s_addr}:{source_port} → {d_addr}:{dest_port}"
                
                # Create user-friendly packet object
                packet_info = {
                    "number": packet_id,
                    "time": timestamp,
                    "source": s_addr,
                    "destination": d_addr,
                    "protocol": proto_name,
                    "length": len(raw_data),
                    "info": info,
                    "raw": raw_data
                }
                
                # Add to packet list and update GUI
                self.captured_packets.append(packet_info)
                self.root.after(0, lambda: self.add_packet_to_tree(packet_info))
            
            # Disable promiscuous mode if on Windows
            if windows_mode:
                conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                
            conn.close()
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Failed to start capture: {str(e)}"))
            self.root.after(0, self.toggle_capture)

    def add_packet_to_tree(self, packet):
        """Add a packet to the treeview"""
        if not self.check_filter(packet):
            return
            
        self.packet_tree.insert("", "end", values=(
            packet["number"],
            packet["time"],
            packet["source"],
            packet["destination"],
            packet["protocol"],
            packet["length"],
            packet["info"]
        ))
        
        # Update status
        self.status_bar.config(text=f"Captured {len(self.captured_packets)} packets")
        
        # Auto-scroll to bottom
        self.packet_tree.yview_moveto(1.0)

    def on_packet_select(self, event):
        """Display detailed info when a packet is selected"""
        selected_items = self.packet_tree.selection()
        if not selected_items:
            return
            
        # Get selected item index
        item = selected_items[0]
        index = int(self.packet_tree.item(item, "values")[0]) - 1  # Convert to 0-based index
        
        # Show packet details if index is valid
        if 0 <= index < len(self.captured_packets):
            self.show_packet_details(self.captured_packets[index])

    def show_packet_details(self, packet):
        """Show detailed packet information"""
        # Enable text widget for editing
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete(1.0, tk.END)
        
        details = []
        details.append(f"Packet #{packet['number']} ({packet['protocol']})")
        details.append(f"Captured at: {packet['time']}")
        details.append(f"Length: {packet['length']} bytes")
        details.append("")
        details.append(f"Source: {packet['source']}")
        details.append(f"Destination: {packet['destination']}")
        details.append("")
        details.append(f"Info: {packet['info']}")
        details.append("")
        
        # More detailed info based on protocol
        protocol = packet["protocol"]
        
        if SCAPY_AVAILABLE and isinstance(packet["raw"], bytes) == False:  # If using Scapy
            details.append("--- Detailed Protocol Information ---")
            
            # Format the scapy packet summary for easy reading
            packet_summary = packet["raw"].summary()
            details.append(packet_summary)
            
            details.append("")
            details.append("--- Layer Details ---")
            
            # Loop through layers
            layer = packet["raw"]
            while layer:
                layer_name = layer.name
                details.append(f"\n{layer_name} Layer:")
                
                # Format the layer fields
                for field in layer.fields:
                    value = layer.fields[field]
                    # Convert bytes to hex representation if needed
                    if isinstance(value, bytes):
                        try:
                            value = value.decode('utf-8', errors='ignore')
                        except:
                            value = value.hex()
                    details.append(f"  {field}: {value}")
                
                # Move to next layer
                layer = layer.payload if hasattr(layer, 'payload') else None
                if isinstance(layer, bytes) and len(layer) == 0:
                    layer = None
                    
            # Add payload excerpt if available
            if hasattr(packet["raw"], "payload") and packet["raw"].payload:
                payload = packet["raw"].payload
                if hasattr(payload, "original") and isinstance(payload.original, bytes):
                    details.append("\n--- Payload Excerpt ---")
                    readable_chars = ''.join(chr(c) if 32 <= c <= 126 else '.' for c in payload.original[:200])
                    details.append(readable_chars)
        else:
            # For raw socket capture or when using Scapy but packet is stored as bytes
            raw_data = packet["raw"]
            
            details.append("--- Hexdump ---")
            hex_dump = self.format_hex_dump(raw_data[:200])  # First 200 bytes
            for line in hex_dump:
                details.append(line)
                
            details.append("\n--- ASCII ---")
            ascii_dump = ''.join(chr(c) if 32 <= c <= 126 else '.' for c in raw_data[:200])
            # Format into lines of 16 chars
            ascii_lines = textwrap.wrap(ascii_dump, width=16)
            for line in ascii_lines:
                details.append(line)
        
        # Display details
        self.detail_text.insert(tk.END, '\n'.join(details))
        self.detail_text.config(state=tk.DISABLED)

    def format_hex_dump(self, data):
        """Format binary data as a hexdump"""
        result = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_line = ' '.join(f'{b:02x}' for b in chunk)
            result.append(f"{i:04x}: {hex_line}")
        return result

    def check_filter(self, packet):
        """Check if packet matches current filter"""
        # Protocol filter
        if self.protocol_filter.get() != "All" and packet["protocol"] != self.protocol_filter.get():
            return False
            
        # Text filter
        filter_text = self.filter_text.get().lower()
        if filter_text:
            # Check all text fields for match
            packet_text = (
                str(packet["source"]).lower() + " " +
                str(packet["destination"]).lower() + " " +
                str(packet["protocol"]).lower() + " " +
                str(packet["info"]).lower()
            )
            if filter_text not in packet_text:
                return False
                
        return True

    def apply_filter(self):
        """Apply filter to existing packets"""
        # Clear current display
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
            
        # Re-add packets that match filter
        for packet in self.captured_packets:
            if self.check_filter(packet):
                self.packet_tree.insert("", "end", values=(
                    packet["number"],
                    packet["time"],
                    packet["source"],
                    packet["destination"],
                    packet["protocol"],
                    packet["length"],
                    packet["info"]
                ))
                
        # Update status
        filtered_count = len(self.packet_tree.get_children())
        total_count = len(self.captured_packets)
        self.status_bar.config(text=f"Displaying {filtered_count} of {total_count} packets")

    def clear_packets(self):
        """Clear all captured packets"""
        self.captured_packets = []
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete(1.0, tk.END)
        self.detail_text.config(state=tk.DISABLED)
        self.status_bar.config(text="Ready")

    def save_capture(self):
        """Save captured packets to PCAP file"""
        if not self.captured_packets:
            messagebox.showinfo("Information", "No packets to save")
            return
            
        if not SCAPY_AVAILABLE:
            messagebox.showwarning("Warning", "Saving captures requires the Scapy library")
            return
            
        # Get file path
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
            
        try:
            # Only save packets captured with Scapy
            valid_packets = [p["raw"] for p in self.captured_packets if isinstance(p["raw"], bytes) == False]
            
            if valid_packets:
                wrpcap(file_path, valid_packets)
                messagebox.showinfo("Success", f"Saved {len(valid_packets)} packets to {file_path}")
            else:
                messagebox.showwarning("Warning", "No valid packets to save (only Scapy packets can be saved)")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {str(e)}")

    def load_capture(self):
        """Load packets from PCAP file"""
        if not SCAPY_AVAILABLE:
            messagebox.showwarning("Warning", "Loading captures requires the Scapy library")
            return
            
        # Get file path
        file_path = filedialog.askopenfilename(
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
            
        try:
            # Clear current packets
            self.clear_packets()
            
            # Read packets from file
            packets = rdpcap(file_path)
            
            # Process each packet
            for packet in packets:
                # Create callback for consistent processing
                self.is_running = True  # Temporarily set running to process packets
                
                # Extract packet information (similar to capture_with_scapy)
                timestamp = datetime.fromtimestamp(packet.time).strftime('%H:%M:%S.%f')[:-3]
                
                # Try to get source and destination
                src = ""
                dst = ""
                proto = ""
                length = len(packet)
                info = ""
                
                # Process packet layers (simplified version of capture_with_scapy logic)
                if packet.haslayer('Ether'):
                    src = packet.getlayer('Ether').src
                    dst = packet.getlayer('Ether').dst
                    proto = "Ethernet"
                
                if packet.haslayer('ARP'):
                    src = packet.getlayer('ARP').psrc
                    dst = packet.getlayer('ARP').pdst
                    proto = "ARP"
                    info = f"Who has {dst}? Tell {src}" if packet.getlayer('ARP').op == 1 else f"{src} is at {packet.getlayer('ARP').hwsrc}"
                
                if packet.haslayer('IP'):
                    src = packet.getlayer('IP').src
                    dst = packet.getlayer('IP').dst
                    
                if packet.haslayer('TCP'):
                    proto = "TCP"
                    sport = packet.getlayer('TCP').sport
                    dport = packet.getlayer('TCP').dport
                    info = f"{src}:{sport} → {dst}:{dport}"
                    
                    if sport == 80 or dport == 80:
                        proto = "HTTP"
                    elif sport == 443 or dport == 443:
                        proto = "HTTPS"
                        
                elif packet.haslayer('UDP'):
                    proto = "UDP"
                    sport = packet.getlayer('UDP').sport
                    dport = packet.getlayer('UDP').dport
                    info = f"{src}:{sport} → {dst}:{dport}"
                    
                    # DNS detection
                    if sport == 53 or dport == 53:
                        proto = "DNS"
                        if packet.haslayer('DNS'):
                            dns_info = []
                            if packet.getlayer('DNS').qr == 0:  # Query
                                for i in range(packet.getlayer('DNS').qdcount):
                                    if packet.getlayer('DNS').qd:
                                        dns_info.append(f"Query: {packet.getlayer('DNS').qd.qname.decode('utf-8', errors='ignore').rstrip('.')}")
                            else:  # Response
                                dns_info.append(f"Response: {packet.getlayer('DNS').ancount} answers")
                            
                            if dns_info:
                                info += f" [{', '.join(dns_info)}]"
                
                elif packet.haslayer('ICMP'):
                    proto = "ICMP"
                    icmp_type = packet.getlayer('ICMP').type
                    icmp_code = packet.getlayer('ICMP').code
                    
                    if icmp_type == 8:
                        info = "Echo (ping) request"
                    elif icmp_type == 0:
                        info = "Echo (ping) reply"
                    else:
                        info = f"Type: {icmp_type}, Code: {icmp_code}"
                
                # Create user-friendly packet object
                packet_info = {
                    "number": len(self.captured_packets) + 1,
                    "time": timestamp,
                    "source": src,
                    "destination": dst,
                    "protocol": proto,
                    "length": length,
                    "info": info,
                    "raw": packet
                }
                
                # Add to packet list
                self.captured_packets.append(packet_info)
                self.add_packet_to_tree(packet_info)
                
            self.is_running = False  # Reset running state
            messagebox.showinfo("Success", f"Loaded {len(packets)} packets from {file_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file: {str(e)}")
            self.is_running = False  # Ensure running state is reset

    def toggle_theme(self):
        """Toggle between light and dark mode"""
        if self.dark_mode.get():
            # Dark mode
            style = ttk.Style()
            style.theme_use('clam')  # Use a theme that supports custom colors
            
            # Configure colors
            style.configure(".", background="#2E2E2E", foreground="#E0E0E0")
            style.configure("Treeview", background="#3C3C3C", fieldbackground="#3C3C3C", foreground="#E0E0E0")
            style.map("Treeview", background=[("selected", "#505050")])
            style.configure("TLabelframe", background="#2E2E2E", foreground="#E0E0E0")
            style.configure("TLabelframe.Label", background="#2E2E2E", foreground="#E0E0E0")
            style.configure("TButton", background="#3C3C3C", foreground="#E0E0E0")
            style.map("TButton", background=[("active", "#505050")])
            
            # Configure text widgets
            self.detail_text.config(background="#3C3C3C", foreground="#E0E0E0", insertbackground="#E0E0E0")
            
            # Configure root
            self.root.configure(bg="#2E2E2E")
            self.main_frame.configure(style="TFrame")
            
            # Status bar
            self.status_bar.configure(background="#2E2E2E", foreground="#E0E0E0")
        else:
            # Light mode
            style = ttk.Style()
            style.theme_use('clam')  # Reset to default theme
            
            # Configure colors back to default
            style.configure(".", background=self.root.cget("background"), foreground="black")
            style.configure("Treeview", background="white", fieldbackground="white", foreground="black")
            style.map("Treeview", background=[("selected", "#0078D7")])
            style.configure("TLabelframe", background=self.root.cget("background"))
            style.configure("TLabelframe.Label", background=self.root.cget("background"))
            style.configure("TButton")
            
            # Configure text widgets
            self.detail_text.config(background="white", foreground="black", insertbackground="black")
            
            # Configure root
            self.root.configure(bg=self.root.cget("background"))
            
            # Status bar
            self.status_bar.configure(background=self.root.cget("background"), foreground="black")

    def show_about(self):
        """Show about dialog"""
        messagebox.showinfo(
            "About Simple Packet Sniffer",
            "Simple Packet Sniffer v1.0\n\n"
            "A simple packet capturing and analysis tool built with Python.\n\n"
            "Features:\n"
            "- Live packet capture\n"
            "- Protocol identification\n"
            "- Packet filtering\n"
            "- Save/load captures\n\n"
            "Dependencies:\n"
            f"- Scapy: {'Installed' if SCAPY_AVAILABLE else 'Not Installed'}\n\n"
            "Note: For full functionality, install Scapy using:\n"
            "pip install scapy"
        )

    def on_closing(self):
        """Handle window closing"""
        if self.is_running:
            self.is_running = False
            time.sleep(0.5)  # Give capture thread time to close
        self.root.destroy()

def main():
    root = tk.Tk()
    app = PacketSniffer(root)
    
    # Check if running as root/admin
    try:
        if os.name == 'posix' and os.geteuid() != 0:
            messagebox.showwarning(
                "Permission Warning",
                "This application may require root/administrator privileges to capture packets.\n"
                "Some functionality might be limited."
            )
        elif os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
            messagebox.showwarning(
                "Permission Warning",
                "This application may require administrator privileges to capture packets.\n"
                "Some functionality might be limited."
            )
    except Exception as e:
        messagebox.showwarning(
            "Permission Check",
            f"Could not verify administrator privileges: {str(e)}\n"
            "Some functionality might be limited."
        )
        
    root.mainloop()

if __name__ == "__main__":
    main()