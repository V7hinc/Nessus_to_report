#!/usr/bin/env python
# -*- coding:utf-8 -*-

import sys
from bs4 import BeautifulSoup
from lxml import etree
import sqlite3
import unicodecsv as ucsv


class NessusVulInfo(object):
    ip = ''
    port = ''
    level = ''
    name = ''
    description = ''
    solution = ''
    plugin_id = ''

    def print_self(self):
        print('IP地址:', self.ip)
        print('端口号:', self.port)
        print('漏洞等级:', self.level)
        print('漏洞名称:', self.name)
        print('漏洞描述:', self.description)
        print('解决办法:', self.solution)
        print('插件编号:', self.plugin_id)
        print()


# 漏洞列表
vuls = []


def select(ip, id):
    conn = sqlite3.connect('vuln.db')
    # 很重要,python3处理需用bytes否则还是乱码
    conn.text_factory = bytes
    cursor = conn.cursor()

    for row in cursor.execute("select * from VULNDB where Plugin_ID=?", (id,)):
        # 根据插件编码获取漏洞等级,漏洞描述,解决方法
        level = str(row[2], encoding='gbk')
        description = str(row[3], encoding='gbk')
        solution = str(row[4], encoding='gbk')
        return ip, level, description, solution


def extract(filename):
    with open(filename, 'r', encoding='utf-8') as fr:
        html = fr.read()
    bs = BeautifulSoup(html, "html.parser")

    html = etree.parse(filename, etree.HTMLParser())
    path = '/html/body/div[1]/div[3]/div'
    ls = html.xpath(path)

    index = 0
    for line in ls:
        # 提取ip地址
        vul = NessusVulInfo()
        vul.ip = ls[0].text
        tmp = etree.tostring(line)
        if b"this.style.cursor" in tmp:
            html_id = line.attrib['id']
            index += 1
            containner_id = '{}{}'.format(html_id, '-container')
            vul.plugin_id, vul.name = line.text.split(' - ')
            # print(vul.plugin_id, vul.name)

            port = bs.find('div', id=containner_id).h2.get_text()
            vul.port = port

            print(vul.ip, '--', vul.port, '--', vul.plugin_id)
            tmp = select(vul.ip, vul.plugin_id)
            if tmp:
                _, vul.level, vul.description, vul.solution = tmp
            else:
                vul.level = u'信息泄露'
            print('======>', tmp)
            vul.print_self()
            vuls.append(vul)
            break
    print(index)


def save2file():
    print('==> saving file...')
    with open('result.csv', 'wb') as f:
        w = ucsv.writer(f, encoding='gbk')
        title = [u'服务器IP', u'端口', u'漏洞名称', u'风险级别', u'漏洞描述', u'修复建议']
        w.writerow(title)
        for vul in vuls:
            data = vul.ip, vul.port, vul.name, vul.level, vul.description, vul.solution
            w.writerow(data)
            pass

if __name__ == '__main__':
    filename = sys.argv[1]
    extract(filename)
    save2file()
    pass