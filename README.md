import tkinter as tk
from tkinter import messagebox
import requests
import socket
import pyperclip

def get_ip_info():
    ip = ip_entry.get()
    url = f"https://rest.db.ripe.net/search.json?query-string={ip}&type-filter=inetnum"
    response = requests.get(url)
    data = response.json()
    
    if "objects" in data and "object" in data["objects"]:
        ip_info = data["objects"]["object"][0]
        inetnum = ip_info.get("primary-key").get("attribute")[0].get("value")
        netname = ip_info.get("attributes").get("attribute")[1].get("value")
        country_code = ""
        for attr in ip_info.get("attributes").get("attribute"):
            if attr.get("name") == "country":
                country_code = attr.get("value")
                break
        created = ""
        last_modified = ""
        for attr in ip_info.get("attributes").get("attribute"):
            if attr.get("name") == "created":
                created = attr.get("value")
            elif attr.get("name") == "last-modified":
                last_modified = attr.get("value")
        
        ip_info_text = f"IP: {ip}\nCountry: {country_code}\nInetnum: {inetnum}\nNetname: {netname}\nCreated: {created}\nLast Modified: {last_modified}"
        messagebox.showinfo("IP Info", ip_info_text)
        pyperclip.copy(ip_info_text)
    else:
        messagebox.showerror("Error", "Ma'lumot topilmadi")

def get_role_info(role_id):
    url = f"https://rest.db.ripe.net/search.json?query-string={role_id}&type-filter=role"
    response = requests.get(url)
    data = response.json()
    if "objects" in data and "object" in data["objects"]:
        role_info = data["objects"]["object"][0]
        address = role_info.get("attributes").get("attribute")[0].get("value")
        org = role_info.get("attributes").get("attribute")[2].get("value")
        org_type = role_info.get("attributes").get("attribute")[3].get("value")
        phone1 = role_info.get("attributes").get("attribute")[4].get("value")
        phone2 = role_info.get("attributes").get("attribute")[5].get("value")
        fax = role_info.get("attributes").get("attribute")[6].get("value")
        return f"Address: {address}, Org: {org}, Org Type: {org_type}, Phone1: {phone1}, Phone2: {phone2}, Fax: {fax}"
    else:
        return "Ma'lumot topilmadi"

def check_ports(ip, ports):
    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((ip, port))
                if result == 0:
                    open_ports.append(port)
        except Exception as e:
            print(f"Xatolik: {e}")
    return open_ports

def display_open_ports():
    ip = ip_entry.get()
    ports = [21, 22, 23, 25, 53, 80, 110, 143, 443]  # Ochiq bo'lishi mumkin bo'lgan eng ko'p ishlatiladigan portlar diapazoni
    open_ports = check_ports(ip, ports)
    if open_ports:
        messagebox.showinfo("Ochiq Portlar", f"Ochiq portlar: {', '.join(map(str, open_ports))}")
    else:
        messagebox.showinfo("Ochiq Portlar", "Ochiq port topilmadi")

def save_ip_info():
    ip = ip_entry.get()
    url = f"https://rest.db.ripe.net/search.json?query-string={ip}&type-filter=inetnum"
    response = requests.get(url)
    data = response.json()
    
    if "objects" in data and "object" in data["objects"]:
        ip_info = data["objects"]["object"][0]
        inetnum = ip_info.get("primary-key").get("attribute")[0].get("value")
        netname = ip_info.get("attributes").get("attribute")[1].get("value")
        country_code = ""
        for attr in ip_info.get("attributes").get("attribute"):
            if attr.get("name") == "country":
                country_code = attr.get("value")
                break
        created = ""
        last_modified = ""
        for attr in ip_info.get("attributes").get("attribute"):
            if attr.get("name") == "created":
                created = attr.get("value")
            elif attr.get("name") == "last-modified":
                last_modified = attr.get("value")
        
        ip_info_text = f"IP: {ip}\nCountry: {country_code}\nInetnum: {inetnum}\nNetname: {netname}\nCreated: {created}\nLast Modified: {last_modified}"
        with open("ip_info.txt", "w") as f:
            f.write(ip_info_text)
        messagebox.showinfo("Save", "Ma'lumotlar saqlandi")
    else:
        messagebox.showerror("Error", "Ma'lumot topilmadi")

root = tk.Tk()
root.title("IP Scanner")

ip_label = tk.Label(root, text="IP Manzil:")
ip_label.grid(row=0, column=0, padx=10, pady=10)

ip_entry = tk.Entry(root)
ip_entry.grid(row=0, column=1, padx=10, pady=10)

scan_button = tk.Button(root, text="Scan", command=get_ip_info)
scan_button.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="we")

port_button = tk.Button(root, text="Ochiq Portlarni Tekshirish", command=display_open_ports)
port_button.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="we")

save_button = tk.Button(root, text="Ma'lumotlarni Saqlash", command=save_ip_info)
save_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10, sticky="we")

root.mainloop()

