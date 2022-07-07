import configparser
import shodan
from tkinter import *
from PIL.ImageTk import PhotoImage
from exp.Thinkphp_5_0_x_getshell import *
from exp.CVE_2022_22954 import *
from exp.spring4shell_exp import *
from exp.hkv_rce import *
from exp.xrk_rce import *
from exp.CVE_2022_26134 import *
from exp.yync_rce import *
from exp.sonicwall_ssl_vpn import *
from exp.yyu8_testsql import *
from exp.CVE_2022_23337 import *
from exp.f5_big_ip import *
from exp.harbor import *
from exp.dvr_login_bypass import *
from exp.metabase_readfile import *
from exp.ruijie_admin_passwd_leak import *
from exp.magicflow_readfile import *
from exp.CVE_2022_8515 import *
from exp.CVE_2020_25078 import *
from exp.fumengyun_sql import *
from exp.VOS3000_readfile import *
from exp.kkFileView_readfile_CVE_2021_43734 import *
from exp.CVE_2022_29464 import *
import json
import threading
from tkinter.messagebox import *
import ttkbootstrap as ttk
import urllib.parse
import urllib.request
import re
import threadpool
import urllib.parse
import urllib.request
import ssl
from urllib.error import HTTPError
import time
import tldextract
from fake_useragent import UserAgent
import os
import requests
import base64
window = tk.Tk()
window.title("Serein [A multi-nday batch exploit tool]    Copyright © 2022    By: W01fh4cker    [Disclaimer: It is forbidden to use this software for illegal operations, otherwise you will be responsible for the consequences!]")
window.geometry('1755x820')
window.resizable(0, 0)
logo = PhotoImage(file="./logo.ico")
window.tk.call('wm', 'iconphoto', window._w, logo)
notebook = ttk.Notebook(window,bootstyle="info")
frameOne = ttk.Frame(window)
frameTwo = ttk.Frame(window)
frameSix = ttk.Frame(window)
frameThree = ttk.Frame(window)
frameFour = ttk.Frame(window)
frameFive = ttk.Frame(window)

def show_about():
    showinfo("About the author", "A country lover, a travel lover.\nCodes build our world.\nWeChat: W01fh4cker\nGitHub：http://github.com/W01fh4cker\nmy blog：http://www.w01f.org")
def show_help():
    showinfo("Having trouble?","Please contact WeChat : W01fh4cker immediately")
def getFofaConfig(section, key):
    config = configparser.ConfigParser()
    a = os.path.split(os.path.realpath(__file__))
    path = 'fofa_configuration.conf'
    config.read(path)
    return config.get(section, key)

def getHunterConfig(section, key):
    config = configparser.ConfigParser()
    a = os.path.split(os.path.realpath(__file__))
    path = 'hunter_configuration.conf'
    config.read(path)
    return config.get(section, key)

def getShodanConfig(section, key):
    config = configparser.ConfigParser()
    a = os.path.split(os.path.realpath(__file__))
    path = 'shodan_configuration.conf'
    config.read(path)
    return config.get(section, key)

def fofa_saveit_first():
    email = fofa_text1.get()
    key = fofa_text2.get()
    with open("fofa_configuration.conf","a+") as f:
        f.write(f"[data]\nemail={email}\nkey={key}")
        f.close()
    showinfo("Successfully saved!","Please keep using the fofa search module! Next time it will be read automatically, no more configuration needed!")
    text3.insert(END,f"[+]Successfully saved!Please keep using the fofa search module! Next time it will be read automatically, no more configuration needed!Your email is:{email};To protect your privacy, the api-key will not be displayed.\n")
    text3.see(END)
    fofa_info.destroy()
def fofa_saveit_twice():
    global email_r,key_r
    if not os.path.exists("fofa_configuration.conf"):
        fofa_saveit_first()
    else:
        email_r = getFofaConfig("data", "email")
        key_r = getFofaConfig("data", "key")

def fofa_info():
    global fofa_info,fofa_text1,fofa_text2,fofa_text3
    fofa_info = Toplevel()
    fofa_info.title("fofa_configuration")
    fofa_info.geometry('355x130')
    fofa_info.resizable(0, 0)
    logo = PhotoImage(file="./logo.ico")
    fofa_info.tk.call('wm', 'iconphoto', fofa_info._w, logo)
    fofa_email = tk.StringVar(fofa_info,value="Fill in the registered email of fofa")
    fofa_text1 = ttk.Entry(fofa_info, bootstyle="success", width=40, textvariable=fofa_email)
    fofa_text1.grid(row=0, column=1, padx=5, pady=5)
    fofa_key = tk.StringVar(fofa_info,value="Fill in the key corresponding to the email")
    fofa_text2 = ttk.Entry(fofa_info, bootstyle="success", width=40, textvariable=fofa_key)
    fofa_text2.grid(row=1, column=1, padx=5, pady=5)
    button1 = ttk.Button(fofa_info, text="save", command=fofa_saveit_twice, width=40, bootstyle="info")
    button1.grid(row=2, column=1, padx=5, pady=5)
    fofa_info.mainloop()

def hunter_saveit_first():
    hunter_apikey = hunter_text1.get()
    hunter_cooki = hunter_text2.get()
    with open("hunter_configuration.conf","a+") as f:
        f.write(f"[data]\nhunter_api_key={hunter_apikey}\nhunter_cookie={hunter_cooki}")
        f.close()
    showinfo("Successfully saved! ","Please keep using hunter to search for modules! Next time it will be read automatically, no more configuration needed!")
    text15.insert(END,f"[+]Successfully saved! Please keep using hunter to search for modules! Next time it will be read automatically, no more configuration needed! To protect your privacy, Hunter platform api-keys and cookies are not displayed.\n")
    text15.see(END)
    hunter_info.destroy()
def hunter_saveit_twice():
    global hunter_api_key,hunter_cookie
    if not os.path.exists("hunter_configuration.conf"):
        hunter_saveit_first()
    else:
        hunter_api_key = getHunterConfig("data", "hunter_api_key")
        hunter_cookie = getHunterConfig("data", "hunter_cookie")

def hunter_info():
    global hunter_info,hunter_text1,hunter_text1,hunter_text2
    hunter_info = Toplevel()
    hunter_info.title("hunter_configuration")
    hunter_info.geometry('768x150')
    hunter_info.resizable(0, 0)
    logo = PhotoImage(file="./logo.ico")
    hunter_info.tk.call('wm', 'iconphoto', hunter_info._w, logo)
    hunter_api_key = tk.StringVar(hunter_info,value="Fill in hunter's api-key")
    hunter_text1 = ttk.Entry(hunter_info, bootstyle="success", width=92, textvariable=hunter_api_key)
    hunter_text1.grid(row=0, column=0, padx=5, pady=5)
    hunter_cookie = tk.StringVar(hunter_info,value="Fill in the base64 encrypted cookie of http://hunter.qianxin.com(Take care to remove the equal sign at the end)")
    hunter_text2 = ttk.Entry(hunter_info, bootstyle="success", width=92, textvariable=hunter_cookie)
    hunter_text2.grid(row=1, column=0, padx=5, pady=5)
    hunter_button = ttk.Button(hunter_info, text="Save (if you need to modify the configuration, \nplease modify the [hunter configuration.conf] in the current directory by yourself)", command=hunter_saveit_twice, width=92, bootstyle="info")
    hunter_button.grid(row=2, column=0, padx=5, pady=5)
    hunter_info.mainloop()

def shodan_saveit_first():
    key = shodan_key_text.get()
    with open("shodan_configuration.conf","a+") as f:
        f.write(f"[data]\nshodan_api_key={key}")
        f.close()
    showinfo("Successfully saved!","Please keep using shodan to search for modules! Next time it will be read automatically, no more configuration needed!")
    shodan_log_text.insert(END,f"[+]Successfully saved! Please keep using shodan to search for modules! Next time it will be read automatically, no more configuration needed!\n")
    shodan_log_text.see(END)
    shodan_info.destroy()

def shodan_saveit_twice():
    global shodan_api_key
    if not os.path.exists("shodan_configuration.conf"):
        showerror("error","You haven't configured the shodan module yet! Please reopen the software and click [Software Configuration--Shodan Configuration] in the upper right corner to configure.")
        shodan_info()
    else:
        shodan_api_key = getShodanConfig("data", "shodan_api_key")

def shodan_info():
    global shodan_info,shodan_key_text
    shodan_info = Toplevel()
    shodan_info.title("shodan_configuration")
    shodan_info.geometry('300x80')
    shodan_info.resizable(0, 0)
    logo = PhotoImage(file="./logo.ico")
    shodan_info.tk.call('wm', 'iconphoto', shodan_info._w, logo)
    shodan_key = tk.StringVar(shodan_info,value="Fill in your key")
    shodan_key_text = ttk.Entry(shodan_info, bootstyle="success", width=33, textvariable=shodan_key)
    shodan_key_text.grid(row=0, column=0, padx=5, pady=5)
    shodan_key_button = ttk.Button(shodan_info, text="Save", command=shodan_saveit_first, width=33, bootstyle="info")
    shodan_key_button.grid(row=1, column=0, padx=5, pady=5)
    shodan_info.mainloop()
def app_proxy():
    showinfo("hey!","This hasn't happened yet~\nIt's on my To-do List!")

menubar = ttk.Menu(window)
loginmenu = ttk.Menu(menubar,tearoff=0)
menubar.add_cascade(label='Software configuration',menu=loginmenu)
loginmenu.add_command(label='fofa_configuration',command=fofa_info)
loginmenu.add_command(label='hunter_configuration',command=hunter_info)
loginmenu.add_command(label='shodan_configuration',command=shodan_info)
loginmenu.add_command(label='proxy',command=app_proxy)
aboutmenu = ttk.Menu(menubar,tearoff=0)
menubar.add_cascade(label='About and Help',menu=aboutmenu)
aboutmenu.add_command(label='about me',command=show_about)
aboutmenu.add_command(label='help',command=show_help)
exitmenu = ttk.Menu(menubar,tearoff=0)
menubar.add_cascade(label='exit',menu=exitmenu)
exitmenu.add_command(label='click me out',command=window.destroy)
window.config(menu=menubar)

def fofa():
    fofa_saveit_twice()
    try:
        fofa_yf = text1.get()
        fofa_ts = text2.get()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.60 Safari/537.36'
        }
        url = f"https://fofa.info/api/v1/search/all?email={email_r}&key={key_r}&qbase64={fofa_yf}&size={fofa_ts}".format()
        resp = requests.get(url, headers)
        if resp.status_code == -1:
            showerror('error!', 'Account information is incorrect. Please check if your email and key are filled in correctly!')
            text3.insert(END, chars="[×]error!Account information is incorrect. Please check if your email and key are filled in correctly!\n")
            text3.see(END)
        elif resp.status_code == -4:
            showerror('error!', 'Incorrect request parameters')
            text3.insert(END, chars="[×]error!The request parameters are wrong, please check whether your query statement and the number of query items are filled in correctly (especially the latter)!\n")
            text3.see(END)
        elif resp.status_code == -5:
            showerror('error!', 'System error, please contact WeChat: W01fh4cker!')
            text3.insert(END, chars="[×]error!System error, please contact WeChat: W01fh4cker!\n")
            text3.see(END)
        else:
            res = json.loads((resp.content).decode('utf-8'))
            xlen = len(res["results"])
            showinfo('start collecting', 'The program starts collecting urls, please wait patiently and do not close the program.')
            text3.insert(END, chars="[+]start collecting!The program starts collecting urls, please wait patiently and do not close the program.\n")
            text3.see(END)
            for i in range(xlen):
                with open("urls.txt", "a+") as f:
                    url = res["results"][i][0]
                    f.write(url + "\n")
            for j in range(xlen):
                with open("host.txt", "a+") as f:
                    host = res["results"][j][1]
                    f.write(host + "\n")
            with open("urls.txt", 'r') as f:
                ln = f.readlines()
                for j in ln:
                    url = j.strip()
                    if url[:7] == 'http://' or url[:8] == 'https://':
                        with open("corrected url.txt", 'a+') as f:
                            text3.insert(END, chars=url + "\n")
                            text3.see(END)
                            f.write(url + '\n')
                    else:
                        newurl = 'http://' + str(url)
                        with open("corrected url.txt", 'a+') as f:
                            text3.insert(END, chars=newurl + "\n")
                            text3.see(END)
                            f.write(newurl + '\n')
            showinfo('Successfully saved', 'The file is in your current folder, urls.txt is a collection of all the collected urls, and the urls in corrected url.txt are all added with http/https headers.')
            text3.insert(END, chars="[+]Successfully saved!The file is in your current folder, urls.txt is a collection of all the collected urls, and the urls in corrected url.txt are all added with http/https headers.\n")
            text3.see(END)
            f.close()
    except Exception as error:
        showerror("error!","Please check whether the sentence before base64 is correct (for example, English double quotation marks are converted into Chinese double quotation marks) or whether you have used proxy software;\nIf there is no problem, please contact WeChat: W01fh4cker immediately!")
        text3.insert(END, chars="[×]error!Please check whether the sentence before base64 is correct (for example, English double quotation marks are converted into Chinese double quotation marks) or whether you have used proxy software;\nIf there is no problem, please contact WeChat: W01fh4cker immediately!\n")
        text3.see(END)

def thread_fofa():
    t = threading.Thread(target=fofa)
    t.setDaemon(True)
    t.start()

def hunter_query():
    showinfo('start collecting', 'The program starts collecting urls, please wait patiently and do not close the program.')
    text15.insert(END, chars="[√]The program starts collecting urls, please wait patiently and do not close the program.\n")
    text15.see(END)
    hunter_saveit_twice()
    global i
    global number
    number = 1
    i = 0
    api_key = hunter_api_key
    query_sentence = text8.get()
    hunter_pagenum_to_query = text9.get()
    hunter_per_page_size = text10.get()
    hunter_asset_type = text11.get()
    hunter_start_time = text13.get()
    hunter_end_time = text14.get()
    hunter_status_code = text12.get()
    url = 'https://hunter.qianxin.com/openApi/search?api-key=' + str(api_key) + '&search=' + str(
        query_sentence) + '&page=' + str(hunter_pagenum_to_query) + '&page_size=' + str(hunter_per_page_size) + '&is_web=' + str(
        hunter_asset_type) + '&start_time=' + str(hunter_start_time) + '&end_time' + str(hunter_end_time) + '&status_code=' + str(hunter_status_code)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.4844.74 Safari/537.36',
        'Cookie': hunter_cookie
    }
    resp = requests.get(url=url, headers=headers)
    global res
    res = json.loads((resp.content).decode('utf-8'))
    global first_url
    hunter_res_num = res["data"]["total"]
    if hunter_res_num == "0":
        text15.insert(END, chars=f"[*]Currently, a total of {hunter_res_num} pieces of data have been queried! Please check your statement before base64 encryption and restart the software to query\n")
        text15.see(END)
    else:
        text15.insert(END, chars=f"[*]Currently, a total of {hunter_res_num} pieces of data have been queried!\n")
        text15.see(END)
    for i in range(len(res["data"]["arr"])):
        if (hunter_res_num == 0):
            text15.insert(END, chars="[*]A total of 0 pieces of data have been queried so far.\n")
            text15.see(END)
            break
        else:
            try:
                its_ip = res["data"]["arr"][i]["ip"]
                its_url = res["data"]["arr"][i]["url"]
                if its_ip == "违规数据无法查看" or its_url == "违规数据无法查看":
                    pass
                else:
                    with open("corrected url.txt","a+") as m:
                        m.write(its_url + "\n")
                    with open("host.txt","a+") as m:
                        m.write(its_ip + "\n")
                    if its_ip is None:
                        pass
                    else:
                        first_url = str(its_url)
            except:
                i = i + 1
    consume_quota = res["data"]["consume_quota"]
    rest_quota = res["data"]["rest_quota"]
    text17.insert(END,"[+]" + consume_quota + "\n[+]" + rest_quota + "\n")
    showinfo('Successfully saved', 'The file is in your current folder, urls.txt is a collection of all collected urls, and the urls in corrected url.txt are all added with http/https headers.')
    text15.insert(END, chars="[+]Successfully saved!The file is in your current folder, urls.txt is a collection of all collected urls, and the urls in corrected url.txt are all added with http/https headers.\n")
    text15.see(END)
def check_code():
    if (res["code"] == 200):
        pass
    elif (res["code"] == 401):
        text15.insert(END,"[×]The start/end time parameter is malformed, the format should be2021-01-01 00:00:00\n")
        text15.see(END)
    elif (res["code"] == 401):
        text15.insert(END,"[×]No permission, please check if your api-key and cookie are filled correctly!\n")
        text15.see(END)
    else:
        text15.insert(END,"[×]Other errors, please contact WeChat: W01fh4cker immediately\n")
        text15.see(END)
def save_url():
    with open("corrected url.txt", 'a+', encoding='utf-8') as f:
        f.write(first_url + '\n')
def check_url_format():
    with open("corrected url.txt",'r') as f:
        ln = f.readlines()
        for j in ln:
            url = j.strip()
            if url[:7] == 'http://' or url[:8] == 'https://':
                pass
            else:
                url = 'http://' + str(url)
                with open("corrected url.txt",'w') as h:
                    h.write(url + '\n')
def hunter():
    hunter_query()
    check_code()
    save_url()
    check_url_format()

def shodan_seach():
    shodan_saveit_twice()
    showinfo('start collecting', 'The program starts collecting urls, please wait patiently and do not close the program.')
    shodan_log_text.insert(END, "[√]The program starts collecting urls, please wait patiently and do not close the program.\n")
    shodan_log_text.see(END)
    SHODAN_API_KEY = key
    api = shodan.Shodan(SHODAN_API_KEY)
    api_info = api.info()
    api_info_json = json.dumps(api_info, sort_keys=True, indent=4, separators=(',', ':'))
    shodan_log_text.insert(END, chars=str(api_info_json) + "\n")
    shodan_log_text.see(END)
    try:
        shodan_search_sentence = shodan_yf_text.get()
        shodan_number = shodan_ts_text.get()
        shodan_number = int(shodan_number)
        page_number = shodan_number / 100
        pagenumber = page_number + 1
        pagenumber = int(pagenumber)
        for j in range(1, pagenumber):
            results = api.search(shodan_search_sentence, page=j)
            for i in range(0,100):
                with open('corrected url.txt', 'a+') as f:
                    ip_str = results['matches'][i]['ip_str']
                    port = results['matches'][i]['port']
                    if port is not None:
                        shodan_got_url1 = "https://" + str(ip_str) + ":" + str(port) + '\n'
                        f.write(shodan_got_url1)
                        shodan_log_text.insert(END, chars=shodan_got_url1)
                        shodan_log_text.see(END)
                    else:
                        shodan_got_url2 = "https://" + str(ip_str) + '\n'
                        f.write(shodan_got_url2)
                        shodan_log_text.insert(END, chars=shodan_got_url2)
                        shodan_log_text.see(END)
        showinfo('Successfully saved', 'The file is in [corrected url.txt] under your current folder.')
        shodan_log_text.insert(END, chars="[+]Successfully saved!The file is in [corrected url.txt] under your current folder.\n")
        shodan_log_text.see(END)
    except Exception as e:
        print(e)
        showerror("error","Please check whether your account has permission to call the API to query this statement!")
        shodan_log_text.insert(END,"[×]error,Please check whether your account has permission to call the API to query this statement!\n")
        shodan_log_text.see(END)
def thread_shodan():
    SHODAN_API_KEY = getShodanConfig("data","shodan_api_key")
    max_thread_num = 100
    executor = ThreadPoolExecutor(max_workers=max_thread_num)
    future = executor.submit(shodan_seach, SHODAN_API_KEY)
    
group1 = ttk.LabelFrame(frameOne, text="fofa search module",bootstyle="info")
group1.grid(row=0,column=0,padx=10, pady=10)
notebook.add(frameOne, text='fofa search')
fofa_yf = tk.StringVar(value="Fill in the base64 encrypted fofa query statement")
text1 = ttk.Entry(group1, bootstyle="success", width=40, textvariable=fofa_yf)
text1.grid(row=0, column=0, padx=5, pady=5)
fofa_ts = tk.StringVar(value="Fill in the number of inquiries (according to your own membership)")
text2 = ttk.Entry(group1, bootstyle="success", width=50, textvariable=fofa_ts)
text2.grid(row=0, column=1, padx=5, pady=5)
text3 = scrolledtext.ScrolledText(group1, width=120, height=38)
text3.grid(row=1, columnspan=3, padx=10, pady=10)
button1 = ttk.Button(group1, text="Click to query", command=thread_fofa, width=20, bootstyle="info")
button1.grid(row=0, column=2, padx=5, pady=5)
group2 = ttk.LabelFrame(frameOne, text="fofa query query statement reference",bootstyle="info")
group2.grid(row=0,column=1,padx=10, pady=10)
text5 = scrolledtext.ScrolledText(group2, width=77, height=41)
text5.insert(END,r"""Enter the query statement directly, and search from the title, html content, http header information, and url fields

• title="abc" searches for abc from the title. Example: Beijing's website in the title

• header="abc" searches for abc from http headers. Example: jboss server

• body="abc" searches for abc from the html body. Example: The text contains Hacked by

• domain="qq.com" searches for sites with qq.com as the root domain name. Example: The root domain name is the website of qq.com

• host=".gov.cn" Search for .gov.cn from the url, note that the search should use host as the name. Example: government website, education website

• port="443" to find assets corresponding to port 443. Example: Find assets corresponding to port 443

• ip="1.1.1.1" Search for websites containing 1.1.1.1 from ip, pay attention to search with ip as the name. Example: Query the website whose IP is 220.181.111.1; If you want to query the network segment, you can: ip="220.181.111.1/24", for example, query the assets of network segment C whose IP is 220.181.111.1

• protocol="https" searches for the specified protocol type (valid when port scanning is enabled). Example: Query https protocol assets

• city="Hangzhou" searches for assets in the specified city. Example: Search for assets in a specified city

• region="Zhejiang" searches for assets in the specified administrative region. Example: Searching for assets in a specified borough

• country="CN" searches for assets in the specified country (code). Example: Search for assets in a specified country (code)

• cert="google" to search for assets with google in the certificate (https or imaps, etc.). Example: Search for assets with google in the certificate (https or imaps, etc.)

• banner=users && protocol=ftp Search for assets with users text in the FTP protocol. Example: Search for assets with users text in FTP protocol

• type=service searches all protocol assets, supports both subdomain and service. Example: Search all protocol assets

• os=windows searches for Windows assets. Example: Search for Windows assets

• server=="Microsoft-IIS/7.5" to search for IIS 7.5 servers. Example: Search IIS 7.5 server

• app="Hikvision-Video Surveillance" Search for Hikvision devices, more app rules. Example: Searching for Hikvision devices

• after="2017" && before="2017-10-01" time range segment search. Example: Time range segment search, note: after is greater than and equal to, before is less than, where after="2017" is the data with a date greater than and equal to 2017-01-01, and before="2017-10-01" is Data less than 2017-10-01

• asn="19551" searches for assets with the specified asn. Example: Search for assets with specified asn

• org="Amazon.com, Inc." searches for the assets of the specified org (organization). Example: Search for assets of a specified org (organization)

• base_protocol="udp" searches for assets with the specified udp protocol. Example: Search for assets with specified udp protocol

• is_ipv6=true Search ipv6 assets, only accept true and false. Example: Search for ipv6 assets

• is_domain=true to search for domain assets, only true and false are accepted. Example: Searching assets for a domain name

• ip_ports="80,443" or ports="80,443" to search for ip assets (asset data in ip units) that open ports 80 and 443 at the same time. Example: Search for IPs with ports 80 and 443 open at the same time

• ip_country="CN" searches for ip assets in China (asset data in ip units). Example: Search for IP assets in China

• ip_region="Zhejiang" searches for ip assets in the specified administrative region (asset data in ip units). Example: Searching for assets in a specified borough

• ip_city="Hangzhou" searches for ip assets in the specified city (asset data in ip units). Example: Search for assets in a specified city

• ip_after="2019-01-01" Search for ip assets after 2019-01-01 (asset data in ip units). Example: Search for ip assets after 2019-01-01

• ip_before="2019-01-01" searches for ip assets before 2019-01-01 (asset data in ip units). Example: Search for ip assets before 2019-01-01

Advanced search: You can use symbols such as parentheses and && || !=, as in

title="powered by" && title!=discuz

title!="powered by" && body=discuz

(body="content=\"WordPress" || (header="X-Pingback" && header="/xmlrpc.php" && body="/wp-includes/")) && host="gov.cn"

The new == exact match symbol can speed up the search. For example, to find all hosts of qq.com, it can be domain=="qq.com"

For the search query statement of website building software, please refer to: Component List

Precautions:

* If the query expression has multiple AND or relationships, try to include them in () outside

The rest, it's time to use your imagination ;)""")
text5.config(state='disabled')
text5.grid(row=0, column=0, padx=10, pady=10)
notebook.add(frameFive, text='hunter search')
group9 = ttk.LabelFrame(frameFive, text="hunter search module",bootstyle="info")
group9.grid(row=0,column=0,padx=5, pady=5)
hunter_query_sentence = tk.StringVar(group9, value="Fill in the encrypted hunter statement")
text8 = ttk.Entry(group9, bootstyle="success", width=45, textvariable=hunter_query_sentence)
text8.grid(row=0, column=0, padx=5, pady=5)
hunter_pagenum_to_query = tk.StringVar(group9, value="Fill in the page number you want to query data")
text9 = ttk.Entry(group9, bootstyle="success", width=35, textvariable=hunter_pagenum_to_query)
text9.grid(row=0, column=1, padx=5, pady=5)
hunter_per_page_size = tk.StringVar(group9, value="Fill in the number of pieces of data you want to query on this page")
text10 = ttk.Entry(group9, bootstyle="success", width=35, textvariable=hunter_per_page_size)
text10.grid(row=0, column=2, padx=5, pady=5)
hunter_asset_type = tk.StringVar(group9, value="Fill in the asset type, 1 for 'web assets', 2 for 'non-web assets', 3 for 'all'")
text11 = ttk.Entry(group9, bootstyle="success", width=52, textvariable=hunter_asset_type)
text11.grid(row=0, column=3, padx=5, pady=5)
hunter_status_code_select = tk.StringVar(group9, value="List of status codes, separated by commas, such as '200'")
text12 = ttk.Entry(group9, bootstyle="success", width=45, textvariable=hunter_status_code_select)
text12.grid(row=1, column=0, padx=5, pady=5)
hunter_start_time = tk.StringVar(group9, value="Start time, the format is 2021-01-01 00:00:00")
text13 = ttk.Entry(group9, bootstyle="success", width=35, textvariable=hunter_start_time)
text13.grid(row=1, column=1, padx=5, pady=5)
hunter_end_time = tk.StringVar(group9, value="End time, the format is 2022-01-01 00:00:00")
text14 = ttk.Entry(group9, bootstyle="success", width=35, textvariable=hunter_end_time)
text14.grid(row=1, column=2, padx=5, pady=5)
hunter_query_button = ttk.Button(group9,text="Click to query",command=hunter,width=51,bootstyle="primary")
hunter_query_button.grid(row=1,column=3,columnspan=2,padx=5,pady=5)
text15 = scrolledtext.ScrolledText(group9,width=178, height=15)
text15.grid(row=2,column=0,columnspan=4,padx=5,pady=5)
group10 = ttk.LabelFrame(frameFive, text="hunter query query statement reference",bootstyle="info")
group10.grid(row=1,column=0,padx=5, pady=5)
text16 = scrolledtext.ScrolledText(group10,width=178, height=19)
text16.grid(row=0,column=0,padx=5,pady=5)
text16.insert(END,"[+]For query statement query, please refer to the documentation:https://hunter.qianxin.com/home/helpCenter?r=2-2\n")
text16.see(END)
group11 = ttk.LabelFrame(frameFive, text="Hunter Points Details",bootstyle="info")
group11.grid(row=0,rowspan=2,column=1,padx=5, pady=5)
text17 = scrolledtext.ScrolledText(group11,width=23, height=42)
text17.grid(row=0,column=0,padx=5,pady=5)

notebook.add(frameSix, text='Shodan Search')
shodan_search_group = ttk.LabelFrame(frameSix, text="Shodan search module",bootstyle="info")
shodan_log_text = scrolledtext.ScrolledText(shodan_search_group,width=112, height=40)
shodan_log_text.grid(row=1,columnspan=3,padx=5,pady=5)
shodan_yf = tk.StringVar(value="Fill in the shodan query statement directly (no encryption required)")
shodan_yf_text = ttk.Entry(shodan_search_group, bootstyle="success", width=50, textvariable=shodan_yf)
shodan_yf_text.grid(row=0, column=0, padx=5, pady=5)
shodan_ts = tk.StringVar(value="Fill in the number of inquiries (according to your own membership)")
shodan_ts_text = ttk.Entry(shodan_search_group, bootstyle="success", width=35, textvariable=shodan_ts)
shodan_ts_text.grid(row=0,column=1,padx=5, pady=5)
shodan_search_button = ttk.Button(shodan_search_group, text="Click to query", command=thread_shodan, width=20, bootstyle="info")
shodan_search_button.grid(row=0, column=2, padx=5, pady=5)
shodan_search_group.grid(row=0,column=0,padx=5, pady=5)
shodan_yufa_group = ttk.LabelFrame(frameSix, text="Shodan Syntax Reference",bootstyle="info")
shodan_yufa_group.grid(row=0,column=1,padx=5, pady=5)
shodan_yufa_text = scrolledtext.ScrolledText(shodan_yufa_group,width=89, height=42)
shodan_yufa_text.grid(row=1,column=4,padx=5,pady=5)
shodan_yufa_text.insert(END,r"""------Limited country and city
Qualified country country: "CN"
Limited city city: "ShangHai"

------ Qualified hostname or domain name
hostname:.org
hostname: "google"
hostname:baidu.com

------Limited organization or institution
org:"alibaba"

------Limited system OS version
os: "Windows Server 2008 R2"
os: "Windows 7 or 8"
os: "Linux 2.6.x"

------Limited port
port:22
port:80

------Specify network segment
net: "59.56.19.0/24"

------Specify the software or product used
product:"Apache httpd"
product: "nginx"
product: "Microsoft IIS httpd"
product: "mysql"

------Specify the CVE vulnerability number
vuln: "CVE-2014-0723"

------Specify web page content
http.html:"hello world"

------ Specify the page title
http.title:"hello"

------ Specifies the return response code
http.status:200

------ Specify the server type in the return
http.server:Apache/2.4.7
http.server:PHP

------Specify geographic location
geo:"31.25,121.44"

------ Designated ISP provider
isp:"China Telecom"
""")
shodan_yufa_text.see(END)
notebook.add(frameTwo, text='nday exploit collection')
group3 = ttk.LabelFrame(frameTwo, text="nday one-click exploit module",bootstyle="info")
group3.grid(row=0,column=0,padx=10, pady=10)
button2 = ttk.Button(group3,text="Spring4shell [auto-muti-exp]",command=spring4shell_gui,width=28,bootstyle="primary")
button2.grid(row=0,column=0,padx=5,pady=5)
button3 = ttk.Button(group3,text="Hikvision RCE [auto-muti-exp]",command=hkv_rce_gui,width=28,bootstyle="primary")
button3.grid(row=0,column=1,padx=5,pady=5)
button4 = ttk.Button(group3,text="Sunlogin RCE [auto-muti-exp]",command=xrk_rce_gui,width=28,bootstyle="primary")
button4.grid(row=0,column=2,padx=5,pady=5)
button5 = ttk.Button(group3,text="ConfulenceONGL RCE [auto-muti-exp]",command=confluence_gui,width=60,bootstyle="info")
button5.grid(row=1,columnspan=2,padx=5,pady=5)
button6 = ttk.Button(group3,text="yonyou NC RCE [auto-muti-exp]",command=yync_rce_gui,width=25,bootstyle="info")
button6.grid(row=0,column=3,padx=5,pady=5)
button7 = ttk.Button(group3,text="SonicWall SSL-VPN RCE [auto-muti-exp]",command=sonicwall_ssl_vpn_gui,width=60,bootstyle="warning")
button7.grid(row=1,column=2,columnspan=2,padx=5,pady=5)
button8 = ttk.Button(group3,text="yonyou U8 OA test.jsp SQLinjection [auto-muti-exp]",command=yyu8_testsql_gui,width=60,bootstyle="warning")
button8.grid(row=0,column=4,padx=5,pady=5)
button9 = ttk.Button(group3,text="Dede v5.7.87 SQLinjection [auto-muti-exp]",command=dedesql_gui,width=60,bootstyle="warning")
button9.grid(row=1,column=4,columnspan=2,padx=5,pady=5)
button10 = ttk.Button(group3,text="F5 BIG-IP RCE [auto-muti-exp]",command=f5_big_ip_gui,width=60,bootstyle="primary")
button10.grid(row=2,columnspan=2,padx=5,pady=5)
button11 = ttk.Button(group3,text="Harbor unauthorized to create administrator [auto-muti-exp]",command=harbor_gui,width=60,bootstyle="primary")
button11.grid(row=2,column=2,columnspan=2,padx=5,pady=5)
button12 = ttk.Button(group3,text="DVR login bypass(CVE-2018-9995) [auto-muti-exp]",command=dvr_login_bypass_gui,width=60,bootstyle="info")
button12.grid(row=2,column=4,columnspan=2,padx=5,pady=5)
button13 = ttk.Button(group3,text="MetaBase arbitrary file read(CVE-2021-41277) [auto-muti-exp]",command=metabase_readfile_gui,width=60,bootstyle="primary")
button13.grid(row=3,column=0,columnspan=2,padx=5,pady=5)
button14 = ttk.Button(group3,text="VMware Server-side template injection(CVE-2022-22954) [auto-muti-exp]",command=vmware_one_access_ssti_gui,width=60,bootstyle="primary")
button14.grid(row=3,column=2,columnspan=2,padx=5,pady=5)
button15 = ttk.Button(group3,text="Thinkphp 5.0.x all-kill getshell [auto-muti-exp]",command=Thinkphp_5_0_x_getshell_gui,width=60,bootstyle="primary")
button15.grid(row=3,column=4,columnspan=2,padx=5,pady=5)
button16 = ttk.Button(group3,text="Ruijie Gateway administrator account password leaked [auto-muti-exp]",command=ruijie_admin_passwd_leak_gui,width=60,bootstyle="info")
button16.grid(row=4,column=0,columnspan=2,padx=5,pady=5)
button17 = ttk.Button(group3,text="MagicFlow firewall gateway reads arbitrary files [auto-muti-exp]",command=magicflow_readfile_gui,width=60,bootstyle="info")
button17.grid(row=4,column=2,columnspan=2,padx=5,pady=5)
button18 = ttk.Button(group3,text="DrayTek Enterprise Network Equipment RCE [auto-muti-exp]",command=vigor_rce_gui,width=60,bootstyle="info")
button18.grid(row=4,column=4,columnspan=2,padx=5,pady=5)
button19 = ttk.Button(group3,text="D-Link monitoring account password information leakage [auto-muti-exp]",command=dcs_admin_passwd_leak_gui,width=60,bootstyle="success")
button19.grid(row=5,column=0,columnspan=2,padx=5,pady=5)
button20 = ttk.Button(group3,text="Fumeng Cloud AjaxMethod.ashx SQLinjection [auto-muti-exp]",command=fumengyun_sql_gui,width=60,bootstyle="success")
button20.grid(row=5,column=2,columnspan=2,padx=5,pady=5)
button21 = ttk.Button(group3,text="Kunshi  virtual operation support system read any file [auto-muti-exp]",command=VOS3000_redfile_gui,width=60,bootstyle="success")
button21.grid(row=5,column=4,columnspan=2,padx=5,pady=5)
button22 = ttk.Button(group3,text="kkFileView getCorsFile arbitrary file read [auto-muti-exp]",command=kkFileView_readfile_CVE_2021_43734_gui,width=60,bootstyle="success")
button22.grid(row=6,column=0,columnspan=2,padx=5,pady=5)
button23 = ttk.Button(group3,text="WSO2 RCE(CVE-2022-29464) [auto-muti-exp]",command=CVE_2022_29464_gui,width=60,bootstyle="success")
button23.grid(row=6,column=2,columnspan=2,padx=5,pady=5)
notebook.add(frameThree, text='IP reverse domain name query + weight query')
def ip138_chaxun(ip, ua):
    ip138_headers = {
        'Host': 'site.ip138.com',
        'User-Agent': ua.random,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate, br',
        'Referer': 'https://site.ip138.com/'
    }
    ip138_url = 'https://site.ip138.com/' + str(ip) + '/'
    try:
        ip138_res = requests.get(url=ip138_url, headers=ip138_headers, timeout=2).text
        if '<li>暂无结果</li>' not in ip138_res:
            result_site = re.findall(r"""</span><a href="/(.*?)/" target="_blank">""", ip138_res)
            return result_site
    except:
        pass

def aizhan_chaxun(ip, ua):
    aizhan_headers = {

        'Host': 'dns.aizhan.com',
        'User-Agent': ua.random,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate, br',
        'Referer': 'https://dns.aizhan.com/'}
    aizhan_url = 'https://dns.aizhan.com/' + str(ip) + '/'
    try:
        aizhan_r = requests.get(url=aizhan_url, headers=aizhan_headers, timeout=2).text
        aizhan_nums = re.findall(r'''<span class="red">(.*?)</span>''', aizhan_r)
        if int(aizhan_nums[0]) > 0:
            aizhan_domains = re.findall(r'''rel="nofollow" target="_blank">(.*?)</a>''', aizhan_r)
            return aizhan_domains
    except:
        pass
def catch_result(i):
    ua_header = UserAgent()
    i = i.strip()
    try:
        ip = i.split(':')[1].split('//')[1]
        ip138_result = ip138_chaxun(ip, ua_header)
        aizhan_result = aizhan_chaxun(ip, ua_header)
        time.sleep(1)
        if ((ip138_result != None and ip138_result != []) or aizhan_result != None):
            with open("ip_reverse_check_result.txt", 'a') as f:
                result = "[url]:" + i + "   " + "[ip138]:" + str(ip138_result) + "  [aizhan]:" + str(aizhan_result)
                text6.insert(END, chars=result + "\n")
                text6.see(END)
                f.write(result + "\n")
        else:
            with open("reverse_check_failure_list.txt", 'a') as f:
                text6.insert(END, chars="[×]"+ i + "Reverse check failed.\n")
                text6.see(END)
                f.write(i + "\n")
    except:
        pass
def ip2domain():
    path = "./"
    files = os.listdir(path)
    for fi in files:
        if 'exist' in fi and 'possible' not in fi and fi.endswith('.txt'):
            filename = "./" + fi
            global url_list
            url_list = open(filename, 'r').readlines()
            url_len = len(open(filename, 'r').readlines())
            if os.path.exists("ip_reverse_check_result.txt"):
                f = open("ip_reverse_check_result.txt", 'w')
                f.truncate()
            if os.path.exists("reverse_check_failure_list.txt"):
                f = open("reverse_check_failure_list.txt", 'w')
                f.truncate()
            max_thread_num = 100
            executor = ThreadPoolExecutor(max_workers=max_thread_num)
            for i in url_list:
                future = executor.submit(catch_result, i)

group5 = ttk.LabelFrame(frameThree, text="Step 1: IP reverse check domain name",bootstyle="info")
group5.grid(row=0,column=1,padx=10, pady=10)
group6 = ttk.LabelFrame(frameThree, text="Step 2: Query Weights",bootstyle="info")
ssl._create_default_https_context = ssl._create_stdlib_context
bd_mb = []
gg = []
global flag
flag = 0
def get_data():
    url_list = open("ip_reverse_check_result.txt").readlines()
    with open("domain.txt", 'w') as f:
        for i in url_list:
            i = i.strip()
            res = i.split('[ip138]:')[1].split('[aizhan]')[0].split(",")[0].strip()
            if res == 'None' or res == '[]':
                res = i.split('[aizhan]:')[1].split(",")[0].strip()
            if res != '[]':
                res = re.sub('[\'\[\]]', '', res)
                ext = tldextract.extract(res)
                res1 = i.split('[url]:')[1].split('[ip138]')[0].strip()
                res2 = "http://www." + '.'.join(ext[1:])
                result = '[url]:' + res1 + '\t' + '[domain]:' + res2
                f.write(result + "\n")
def getPc(domain):
    ua_header = UserAgent()
    headers = {
        'Host': 'baidurank.aizhan.com',
        'User-Agent': ua_header.random,
        'Sec-Fetch-Dest': 'document',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Cookie': ''
    }
    aizhan_pc = 'https://baidurank.aizhan.com/api/br?domain={}&style=text'.format(domain)
    try:
        req = urllib.request.Request(aizhan_pc, headers=headers)
        response = urllib.request.urlopen(req, timeout=10)
        b = response.read()
        a = b.decode("utf8")
        result_pc = re.findall(re.compile(r'>(.*?)</a>'), a)
        pc = result_pc[0]

    except HTTPError as u:
        time.sleep(3)
        return getPc(domain)
    return pc
def getMobile(domain):
    ua_header = UserAgent()
    headers = {
        'Host': 'baidurank.aizhan.com',
        'User-Agent': ua_header.random,
        'Sec-Fetch-Dest': 'document',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Cookie': ''
    }
    aizhan_pc = 'https://baidurank.aizhan.com/api/mbr?domain={}&style=text'.format(domain)
    try:
        req = urllib.request.Request(aizhan_pc, headers=headers)
        response = urllib.request.urlopen(req, timeout=10)
        b = response.read()
        a = b.decode("utf8")
        result_m = re.findall(re.compile(r'>(.*?)</a>'), a)
        mobile = result_m[0]
    except HTTPError as u:
        time.sleep(3)
        return getMobile(domain)
    return mobile
def seo(domain, url):
    try:
        result_pc = getPc(domain)
        result_mobile = getMobile(domain)
    except Exception as u:
        if flag == 0:
            text7.insert(END, chars=f"[!] The detection of target {url} failed, failed.txt has been written to wait for re-detection\n{domain}\n")
            text7.see(END)
            with open('fail.txt', 'a', encoding='utf-8') as o:
                o.write(url + '\n')
        else:
            text7.insert(END, chars=f"[!!]Target {url} failed second detection\n{domain}\n")
            text7.see(END)
    result = '[+] Baidu weight:' + str(result_pc) + '  Mobile Weight:' + str(result_mobile) + '  ' + url
    text7.insert(END, chars=result + "\n")
    text7.see(END)
    if result_pc == '0' and result_mobile == '0':
        gg.append(result)
    else:
        bd_mb.append(result)
    return True
def exp(url):
    try:
        main_domain = url.split('[domain]:')[1]
        ext = tldextract.extract(main_domain)
        domain = '.'.join(ext[1:])
        rew = seo(domain, url)
    except Exception as u:
        pass
def multithreading(funcname, params=[], filename="domain.txt", pools=15):
    works = []
    with open(filename, "r") as f:
        for i in f:
            func_params = [i.rstrip("\n")] + params
            works.append((func_params, None))
    pool = threadpool.ThreadPool(pools)
    reqs = threadpool.makeRequests(funcname, works)
    [pool.putRequest(req) for req in reqs]
    pool.wait()
def google_simple(url, j):
    google_pc = "https://pr.aizhan.com/{}/".format(url)
    bz = 0
    http_or_find = 0
    try:
        response = requests.get(google_pc, timeout=10).text
        http_or_find = 1
        result_pc = re.findall(re.compile(r'<span>google PR：</span><a>(.*?)/></a>'), response)[0]
        result_num = result_pc.split('alt="')[1].split('"')[0].strip()
        if int(result_num) > 0:
            bz = 1
        result = '[+] google weight:' + result_num + '  ' + j
        return result, bz
    except:
        if (http_or_find != 0):
            result = "[!]wrong format:" + "j"
            return result, bz
        else:
            time.sleep(3)
            return google_simple(url, j)
def exec_function():
    if os.path.exists("fail.txt"):
        f = open("fail.txt", 'w', encoding='utf-8')
        f.truncate()
    else:
        f = open("fail.txt", 'w', encoding='utf-8')
    multithreading(exp, [], "domain.txt", 15)
    fail_url_list = open("fail.txt", 'r').readlines()
    if len(fail_url_list) > 0:
        text7.insert(END, chars="*" * 12 + "Starting to redetect failed urls" + "*" * 12 + "\n")
        text7.see(END)
        global flag
        flag = 1
        multithreading(exp, [], "fail.txt", 15)
    with open("weight_list.txt", 'w', encoding="utf-8") as f:
        for i in bd_mb:
            f.write(i + "\n")
        f.write("\n")
        f.write("-" * 25 + "Start detecting Google's weights" + "-" * 25 + "\n")
        f.write("\n")
        text7.insert(END, chars="*" * 12 + "Starting to detect Google's weights" + "*" * 12 + "\n")
        text7.see(END)
        for j in gg:
            main_domain = j.split('[domain]:')[1]
            ext = tldextract.extract(main_domain)
            domain = "www." + '.'.join(ext[1:])
            google_result, bz = google_simple(domain, j)
            time.sleep(1)
            text7.insert(END, chars=google_result + "\n")
            text7.see(END)
            if bz == 1:
                f.write(google_result + "\n")
    text7.insert(END, chars="The detection is completed, the txt has been saved in the current directory\n")
    text7.see(END)
def rankquery():
    get_data()
    exec_function()
group6.grid(row=0,column=2,padx=10, pady=10)
buttonone = ttk.Button(group5,text="IP-->Domain",command=ip2domain,width=99,bootstyle="primary")
buttonone.grid(row=0,column=0,padx=5,pady=5)
buttontwo = ttk.Button(group6,text="query weight",command=rankquery,width=99,bootstyle="primary")
buttontwo.grid(row=0,column=0,padx=5,pady=5)
text6 = tk.Text(group5,width=100,height=35)
text6.grid(row=1,column=0,padx=10,pady=10)
text7 = tk.Text(group6,width=100,height=35)
text7.grid(row=1,column=0,padx=10,pady=10)
notebook.add(frameFour, text='base64 encryption')
group7 = ttk.LabelFrame(frameFour, text="base64 encryption module",bootstyle="info")
group7.grid(row=0,column=0,padx=10, pady=10)
group8 = ttk.LabelFrame(frameFour, text="Common fofa statements and corresponding base64 content",bootstyle="info")
group8.grid(row=0,column=1,padx=10, pady=10)
sentence = tk.StringVar(frameFour, value="Fill in what you want to encrypt")
encode_entry = ttk.Entry(group7, bootstyle="success", width=102, textvariable=sentence)
encode_entry.grid(row=0, column=0, padx=10, pady=10)
encode_text = scrolledtext.ScrolledText(group7, width=100, height=30)
encode_text.grid(row=2, column=0, padx=10, pady=10)
encode_text2 = scrolledtext.ScrolledText(group8, width=98, height=36)
encode_text2.grid(row=2, column=1, padx=10, pady=10)
encode_text2.insert(END,"""["Confluence" && country="CN"]'s encryption result is:IkNvbmZsdWVuY2UiICYmIGNvdW50cnk9IkNOIg==\n\n[app="HIKVISION-视频监控"]'s encryption result is:YXBwPSJISUtWSVNJT04t6KeG6aKR55uR5o6nIg==\n\n[app="TDXK-通达OA"]'s encryption result is:YXBwPSJURFhLLemAmui+vk9BIg==\n\n[(body="login_box_sonicwall" || header="SonicWALL SSL-VPN Web Server") && body="SSL-VPN"]'s encryption result is:KGJvZHk9ImxvZ2luX2JveF9zb25pY3dhbGwiIHx8IGhlYWRlcj0iU29uaWNXQUxMIFNTTC1WUE4gV2ViIFNlcnZlciIpICYmIGJvZHk9IlNTTC1WUE4i\n\n[icon_hash="-335242539"]'s encryption result is:aWNvbl9oYXNoPSItMzM1MjQyNTM5Ig==\n\n[title="Harbor"]'s encryption result is:dGl0bGU9IkhhcmJvciI=\n\n[title="XVR Login"]'s encryption result is:dGl0bGU9IlhWUiBMb2dpbiI=\n\n[app="Metabase"]'s encryption result is:YXBwPSJNZXRhYmFzZSI=\n\n[app="vmware-Workspace-ONE-Access" || app="vmware-Identity-Manager"]'s encryption result is:YXBwPSJ2bXdhcmUtV29ya3NwYWNlLU9ORS1BY2Nlc3MiIHx8IGFwcD0idm13YXJlLUlkZW50aXR5LU1hbmFnZXIi\n\n[app="APACHE-Spark-Jobs"]'s encryption result is:YXBwPSJBUEFDSEUtU3BhcmstSm9icyI=\n\n[header="thinkphp"]'s encryption result is:aGVhZGVyPSJ0aGlua3BocCI=\n\n[app="Ruijie-EG易网关" && port="4430"]'s encryption result is:YXBwPSJSdWlqaWUtRUfmmJPnvZHlhbMiICYmIHBvcnQ9IjQ0MzAi\n\n[app="MSA/1.0"]'s encryption result is:YXBwPSJNU0EvMS4wIg==\n\n[title="Vigor 2960"]'s encryption result is:dGl0bGU9IlZpZ29yIDI5NjAi\n\n[app="D_Link-DCS-2530L"]'s encryption result is:YXBwPSJEX0xpbmstRENTLTI1MzBMIg==\n\n[title="孚盟云 "]'s encryption result is:dGl0bGU9IuWtmuebn+S6kSAi\n\n[app="VOS-VOS3000"]'s encryption result is:YXBwPSJWT1MtVk9TMzAwMCI=\n\n[body="kkFileView"]'s encryption result is:Ym9keT0ia2tGaWxlVmlldyI=\n\n[title="WSO2 Management Console"]'s encryption result is:   dGl0bGU9IldTTzIgTWFuYWdlbWVudCBDb25zb2xlIg==\n\n""")
encode_text2.see(END)
encode_text2.config(state="disabled")
def base64_dec():
    str = encode_entry.get().encode("utf-8")
    str_r = str.decode("utf-8")
    encodestr = base64.b64encode(str)
    str_base64 = encodestr.decode("GB2312")
    encode_text.insert(END,chars=f"[{str_r}]'s encryption result is:{str_base64}\n")
buttonthree = ttk.Button(group7,text="One-click encryption",command=base64_dec,width=101,bootstyle="primary")
buttonthree.grid(row=1,column=0,padx=10,pady=10)
notebook.grid(padx=10, pady=10)
window.mainloop()
