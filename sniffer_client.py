import socket
import json
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import csv
from datetime import datetime

# Client Settings
SERVER_HOST = '10.255.255.254'  # Server address (localhost)
SERVER_PORT = 12345
BUFFER_SIZE = 1024

# GUI Setup
root = tk.Tk()
root.title("🌐 Network Packet Sniffer")
root.geometry("1100x600")
root.config(bg="#1B2631")

# Header Label
header_label = tk.Label(root, text="🌐 Network Packet Sniffer", font=("Arial", 20, "bold"), fg="white", bg="#2C3E50", padx=10, pady=5)
header_label.pack(fill="x")

# Packet Counter
packet_counter_label = tk.Label(root, text="Packets Captured: 0", font=("Arial", 12, "bold"), fg="yellow", bg="#1B2631", padx=10)
packet_counter_label.pack(pady=5)

# Table Frame
frame = tk.Frame(root)
frame.pack(pady=10)
columns = ("Timestamp", "Source MAC", "Destination MAC", "Source IP", "Destination IP", "Protocol", "Size", "Payload")
tree = ttk.Treeview(frame, columns=columns, show="headings")
tree.pack()
for col in columns:
    tree.heading(col, text=col)
    tree.column(col, width=120)

# Treeview Styling
style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview", background="#212F3D", foreground="white", rowheight=25, fieldbackground="#17202A")
style.map("Treeview", background=[("selected", "#566573")])

# Protocol Filter
filter_protocol = tk.StringVar(value="All")
ttk.Combobox(root, textvariable=filter_protocol, values=["All", "TCP", "UDP", "ICMP", "IPv4", "IPv6", "DNS", "ARP"], font=("Arial", 12)).pack(pady=5)

# Button Frame
btn_frame = tk.Frame(root, bg="#1B2631")
btn_frame.pack(pady=10)

# Start Sniffing Function
def start_sniffing():
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((SERVER_HOST, SERVER_PORT))

        def receive_packets():
            while True:
                data = client_socket.recv(BUFFER_SIZE)
                if data:
                    packet_info = json.loads(data.decode())
                    tree.insert("", "end", values=tuple(packet_info.values()))
                    packet_counter_label.config(text=f"Packets Captured: {len(tree.get_children())}")  # Updated here for correct count

        threading.Thread(target=receive_packets, daemon=True).start()

        messagebox.showinfo("Packet Sniffer", "Started sniffing!")
    except Exception as e:
        messagebox.showerror("Connection Error", f"Failed to connect to server: {e}")

# Stop Sniffing Function
def stop_sniffing():
    messagebox.showinfo("Packet Sniffer", "Sniffing Stopped!")

# Export Data Function (JSON and CSV)
def export_data():
    # Ask user to choose the file format (JSON or CSV)
    file_type = messagebox.askquestion("Export Data", "Choose export format:\nYes for JSON, No for CSV.")
    
    if file_type == 'yes':  # Export as JSON
        filename = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if filename:
            try:
                # Gather data from Treeview
                packet_data = []
                for row in tree.get_children():
                    packet_data.append(dict(zip(columns, tree.item(row)["values"])))
                
                # Write to JSON
                with open(filename, 'w') as json_file:
                    json.dump(packet_data, json_file, indent=4)
                messagebox.showinfo("Export Successful", f"Data exported successfully to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export data: {e}")
    
    elif file_type == 'no':  # Export as CSV
        filename = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if filename:
            try:
                # Write data to CSV
                with open(filename, 'w', newline='') as csv_file:
                    writer = csv.DictWriter(csv_file, fieldnames=columns)
                    writer.writeheader()
                    for row in tree.get_children():
                        writer.writerow(dict(zip(columns, tree.item(row)["values"])))
                messagebox.showinfo("Export Successful", f"Data exported successfully to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export data: {e}")

# Clear Captured Packets
def clear_packets():
    tree.delete(*tree.get_children())
    packet_counter_label.config(text="Packets Captured: 0")

tk.Button(btn_frame, text="▶ Start Sniffing", font=("Arial", 14, "bold"), bg="#27AE60", fg="white", padx=10, pady=5, command=start_sniffing).grid(row=0, column=0, padx=5)
tk.Button(btn_frame, text="⏹ Stop Sniffing", font=("Arial", 14, "bold"), bg="#E74C3C", fg="white", padx=10, pady=5, command=stop_sniffing).grid(row=0, column=1, padx=5)
tk.Button(btn_frame, text="💾 Export Data", font=("Arial", 14, "bold"), bg="#2980B9", fg="white", padx=10, pady=5, command=export_data).grid(row=0, column=2, padx=5)
tk.Button(btn_frame, text="🗑 Clear Packets", font=("Arial", 14, "bold"), bg="#F39C12", fg="white", padx=10, pady=5, command=clear_packets).grid(row=0, column=3, padx=5)

root.mainloop()