import socket
from scapy.all import sniff, wrpcap, IP, TCP, UDP
import tkinter as tk
from tkinter.scrolledtext import ScrolledText

# Global variables for file handling
current_file_path = "captured_traffic_1.pcap"
current_file_size = 0
MAX_FILE_SIZE = 500 * 1024  # 500 KB
current_file_index = 1  # To track the current file index

def send_packet(packet):
    global current_file_path, current_file_size

    print("Packet received:", packet.summary())  # Debug print to see if packets are being received

    # Check if the packet contains the IP layer
    if IP in packet:
        # Extract relevant information from the packet
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Check if TCP layer exists
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            protocol = "TCP"
        # Check if UDP layer exists
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            protocol = "UDP"
        # Handle other protocols
        else:
            src_port = "N/A"
            dst_port = "N/A"
            protocol = "Unknown"

        # Create a message containing the packet information
        message = f"Packet: Source - {src_ip}:{src_port}, Destination - {dst_ip}:{dst_port}, Protocol - {protocol}"

        # Write the packet to the PCAP file
        wrpcap(current_file_path, packet, append=True)

        # Update current file size
        current_file_size += len(packet)

        # Display packet information in the UI
        log(message)

        # Check if current file exceeds the maximum size
        if current_file_size >= MAX_FILE_SIZE:
            # Create a new file
            create_new_file()

    else:
        print("Packet does not contain IP layer")  # Debug print to check if packets contain IP layer

def create_new_file():
    global current_file_path, current_file_size, current_file_index

    # Increment file index
    current_file_index += 1
    current_file_path = f"captured_traffic_{current_file_index}.pcap"
    current_file_size = 0

    log(f"New file created: {current_file_path}")

def log(message):
    log_text.insert(tk.END, message + "\n")

def send_files_to_server():
    global current_file_path

    try:
        # Open the current file and send its content to the server
        with open(current_file_path, "rb") as file:
            file_data = file.read()
            client_socket.sendall(file_data)
    except Exception as e:
        print(f"Error sending file to server: {e}")

# Set the server address and port
server_address = '127.0.0.1'
server_port = 9000

# Create a TCP/IP socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Create the main window
root = tk.Tk()
root.title("Packet Sniffer")

# Create a text widget for logging
log_text = ScrolledText(root, width=50, height=20)
log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

try:
    # Connect the socket to the server
    client_socket.connect((server_address, server_port))
    log(f"Connected to server at {server_address}:{server_port}")

    # Start sniffing packets and display them in the UI
    sniff(prn=send_packet, store=0)
    
    # Send each file to the server
    send_files_to_server()

except Exception as e:
    log(f"Error: {e}")

finally:
    # Close the socket
    client_socket.close()

# Run the Tkinter event loop
root.mainloop()
