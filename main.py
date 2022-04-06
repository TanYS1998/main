import requests
import re
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urlparse, urljoin
import colorama
from tkinter import *
from tkinter import messagebox
from PIL import ImageTk, Image

session = requests.Session()
session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
main = Tk()
main.title("Welcome to Shield of Aegis")
main.geometry('500x300')
frame = Frame(main, width=600, height=400)
frame.pack(anchor=W, fill=Y, expand=False, side=LEFT)
frame.place(anchor='center', relx=0.5, rely=0.5)
img = ImageTk.PhotoImage(Image.open("redshag.jpg"))
colorama.init()
RESET = colorama.Fore.RESET
external = set()
internal = set()
total_visit = 0
label = Label(frame, image = img)
label.pack()

def avability_checker(url):
    web = requests.get(url)
    messagebox.showinfo(url, web)
    print(url , web)
    messagebox.showinfo('latency', web.elapsed)
    print(web.elapsed)
    return

def get_scraper(url):
    html = session.get(url).content
    info = bs(html, "html.parser")
    css_files = []
    script_files = []
    for css in info.find_all("link"):
        if css.attrs.get("href"):
            css_url = urljoin(url, css.attrs.get("href"))
            css_files.append(css_url)
    for script in info.find_all("script"):
        if script.attrs.get("src"):
            src_url = urljoin(url, script.attrs.get("src"))
            script_files.append(src_url)
    with open("javascript_files.txt", "w") as f:
        for javascript_file in script_files:
            print(javascript_file, file=f)
    with open("css_files.txt", "w") as f:
        for css_file in css_files:
            print(css_file, file=f)
    print("Total script files:", len(script_files))
    print("Total CSS files:", len(css_files))
    return

def subdomain_scanner(domain):
    file = open("wordlist.txt")
    info = file.read()
    subs = info.splitlines()
    discovered_domain = []
    for subdomain in subs:
        web = f"http://{subdomain}.{domain}"
        try:
            requests.get(web)
        except requests.ConnectionError:
            pass
        else:
            print("Discovered domain:", web)
            discovered_domain.append(web)
            with open("discovered_domains.txt", "w") as f:
                for subdomain in discovered_domain:
                    print(subdomain, file=f)
    return

def data_retriver(url):
    parser = bs(requests.get(url).content, "html.parser")
    return parser.find_all("form")

def form_retriver(form):
    fdetail = {}
    action = form.attrs.get("action").lower()
    method = form.attrs.get("method", "get").lower()
    entry = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        entry.append({"type": input_type, "name": input_name})
    fdetail["action"] = action
    fdetail["method"] = method
    fdetail["inputs"] = entry
    return fdetail

def form_requester(form_fdetail, url, value):
    target_url = urljoin(url, form_fdetail["action"])
    inputs = form_fdetail["inputs"]
    info = {}
    for input in inputs:
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        value = input.get("value")
        name = input.get("name")
        if value and name:
            info[name] = value
    if form_fdetail["method"] == "post":
        return requests.post(target_url, data=info)
    else:
        return requests.get(target_url, params=info)
    return

def xss_scanner(url):
    detail = data_retriver(url)
    print(f"Detected {len(detail)} forms on {url}.")
    script = "<Script>alert('2206')</scripT>"
    is_vulnerable = False
    print(f" No XSS Detected on {url}")
    for form in detail:
        form_details = form_retriver(form)
        content = form_requester(form_details, url, script).content.decode()
        if script in content:
            messagebox.showinfo(url, 'XSS vulnerability Detected')
            print(f"XSS Detected vulnerability on {url}")
            print(f"Form details:")
            pprint(form_details)
            is_vulnerable = True
        else :
            print(f"No XSS vulnerability on {url}")
            messagebox.showinfo(url, 'No XSS vulnerability Detected')
    return

def info_retriver(form):
    fdetail = {}
    # get the form action (target url)
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    fdetail["action"] = action
    fdetail["method"] = method
    fdetail["inputs"] = inputs
    return fdetail

def error(response):
    list = {
        "you have an error in your sql syntax;",
        "warning: mysql",
        "unclosed quotation mark after the character string",
        "quoted string not properly terminated",
    }
    for error in list:
        if error in response.content.decode().lower():
            return True
    return False

def sql_scanner(url):

    for c in "\"'":
        new_url = f"{url}{c}"
        print("Running", new_url)
        res = session.get(new_url)
    forms = data_retriver(url)
    for form in forms:
        form_details = info_retriver(form)
        for c in "\"'":
            info = {}
            for input_tag in form_details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    try:
                        info[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    info[input_tag["name"]] = f"test{c}"
            url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = session.post(url, data=info)
            elif form_details["method"] == "get":
                res = session.get(url, params=info)
            if error(res):
                messagebox.showinfo(url, 'SQL Injection vulnerability detected')
                print("SQL injection vulnerability detected, link:", url)
                print("Form:")
                pprint(form_details)
                break
            else:
                messagebox.showinfo(url, 'No SQL Injection vulnerability detected')
                print("No SQL detected")
                break
    return

def url_extractor(url):
    urls = set()
    dname = urlparse(url).netloc
    info = bs(requests.get(url).content, "html.parser")
    for a_tag in info.findAll("a"):
        href = a_tag.attrs.get("href")
        if href == "" or href is None:
            continue
        href = urljoin(url, href)
        parsed_href = urlparse(href)
        href = parsed_href.scheme + "://" + parsed_href.netloc + parsed_href.path
        if href in internal:
            continue
        if dname not in href:
            if href not in external:
                print(f"External link: {href}{RESET}")
                external.add(href)
            continue
        print(f"Internal link: {href}{RESET}")
        urls.add(href)
        internal.add(href)
    return urls


def crawl_url(url, max=30):
    global total_visit
    total_visit+= 1
    count = url_extractor(url)
    print(f"Crawling: {url}{RESET}")
    for link in count:
        if total_visit > max:
            break
        crawl_url(link, max=max)
        with open("internal_link.txt", "w") as f:
            for link in internal:
                print(link, file=f)
        with open("external_link.txt", "w") as f:
            for link in external:
                print(link, file=f)
    return

def clicked():
    content = entry.get()
    url = content
    avability_checker(url)
    xss_scanner(url)
    sql_scanner(url)
    domain = url.replace("https://", "")
    get_scraper(url)
    crawl_url(url)
    print("Total Internal links:", len(internal))
    print("Total External links:", len(external))
    print("Total URLs:", len(external) + len(internal))
    subdomain_scanner(domain)
    return


entry = Entry(main)
entry.grid(row=0, column=1)
button = Button(main, text="Click Me", command=clicked)
button.grid(column=2, row=0)
entry.bind('<Return>', clicked)
Label(main, text="Please enter the website you wish to scan: ").grid(row=0, sticky=W)
mainloop()


















