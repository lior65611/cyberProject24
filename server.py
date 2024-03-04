import socket
import os
from _thread import *
import threading
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from scapy.all import sniff, wrpcap, rdpcap, Ether, IP, TCP

# Global variables
captured_files_dir = "captured_files/"
current_file_index = 1
current_file_path = f"{captured_files_dir}captured_traffic_{current_file_index}.pcap"
current_file_size = 0
MAX_FILE_SIZE = 500 * 1024  # 500 KB
server_paused = False
pause_event = threading.Event()

# Function to handle client requests
def threaded(c):
    global server_paused
    while True:
        data = c.recv(102400)
        
        # Perform analysis on received data
        analysis_result = perform_analysis(data)
        
        # Save data to new file
        save_data_to_file(data, analysis_result)
        
        # Show UI per client
        show_ui_per_client(analysis_result)
        
        # Save data to database
        save_to_database(data, analysis_result)

# Function to save data to a new file
def save_data_to_file(data, analysis_result):
    global current_file_size, current_file_path
    
    # Format data for saving
    received_id = analysis_result["received_id"]
    ip = analysis_result["ip"]
    port = analysis_result["port"]
    formatted_data = f"{received_id}_{ip}_{port}"
    
    # Check if the server is paused
    if pause_event.is_set():
        pause_event.clear()
        log("Server paused.")
        pause_event.wait()

    with threading.Lock():
        if current_file_size + len(formatted_data) >= MAX_FILE_SIZE:
            # Create a new file before writing the current data
            create_new_file()

        # Write the data to the current file
        with open(current_file_path, "a") as file:
            file.write(formatted_data + "\n")
            current_file_size += len(formatted_data)

# Function to perform analysis on received data
def perform_analysis(data):
    # Perform analysis here
    # For demonstration purposes, returning dummy analysis results
    return {
        "received_id": 1,
        "ip": "192.168.1.1",
        "port": 8080
    }

# Function to show UI per client
def show_ui_per_client(analysis_result):
    # Implement UI per client here
    pass

# Function to save data to database
def save_to_database(data, analysis_result):
    # Save data to database here
    pass

# Function to create a new file
def create_new_file():
    global current_file_index, current_file_path, current_file_size
    current_file_index += 1
    current_file_path = f"{captured_files_dir}captured_traffic_{current_file_index}.pcap"
    current_file_size = 0

# Function to start the server
def start_server():
    global server_paused
    start_button.config(state=tk.DISABLED)
    pause_button.config(state=tk.NORMAL)
    print("Server started.")
    server_thread = threading.Thread(target=Main)
    server_thread.start()

# Function to pause/resume the server
def pause_server():
    global server_paused
    pause_button.config(state=tk.DISABLED)
    if server_paused:
        pause_event.clear()
        log("Server resumed.")
        server_paused = False
    else:
        server_paused = True
        pause_event.set()
        log("Server paused.")
    start_button.config(state=tk.NORMAL)



# Function to log messages in the UI
def log(message):
    log_text.insert(tk.END, message + "\n")

# Server function
def Main():
    global server_paused

    host = '127.0.0.1'
    port = 9000
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    print(f"Socket binded to port {port}")
    s.listen(5)
    print("Socket is listening")
    while True:
        c, addr = s.accept()
        print(f"Connected to : {addr[0]} : {addr[1]}")
        start_new_thread(threaded, (c,))

# Create the main window
root = tk.Tk()
root.title("Network Scanner")

# Create a frame for the buttons
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

# Create buttons for actions
start_button = tk.Button(button_frame, text="Start Server", command=start_server)
start_button.pack(side=tk.LEFT, padx=5)

rescan_button = tk.Button(button_frame, text="Rescan Files", state=tk.NORMAL)
rescan_button.pack(side=tk.LEFT, padx=5)

pause_button = tk.Button(button_frame, text="Pause Server", command=pause_server, state=tk.DISABLED)
pause_button.pack(side=tk.LEFT, padx=5)

# Create a text widget for logging
log_text = ScrolledText(root, width=50, height=20)
log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

# Run the Tkinter event loop
root.mainloop()
