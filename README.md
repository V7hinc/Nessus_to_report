## Nessus_to_report
Nessus报告转中文，原脚本升级至python3。

## 2020-4-19
* 更新至python3
* 增加端口信息
* 解决中文编码问题

[注] 目前仅测试了，处理单个ip的扫描结果。
## Sample

```
# python3 Nessus_report_py3.py 172_16_176_120_nmakpm.html
172.16.176.120 -- tcp/5674 -- 87733
======> ('172.16.176.120', '中危', '远程高级消息队列协议（AMQP）服务支持一个或多个认证机制，允许凭据是以明文方式发送。', '在AMQP配置中禁用明文认证机制。')
IP地址: 172.16.176.120
端口号: tcp/5674
漏洞等级: 中危
漏洞名称: AMQP Cleartext Authentication
漏洞描述: 远程高级消息队列协议（AMQP）服务支持一个或多个认证机制，允许凭据是以明文方式发送。
解决办法: 在AMQP配置中禁用明文认证机制。
插件编号: 87733

...
==> saving file...
```
![image](https://github.com/starnightcyber/Nessus_to_report/blob/master/sample.png?raw=true)

## 说明

Nessus扫描结束，选择HTML类型，Report选择Custom，Group By 选择Host，导出HTML报告。

## Origin

原作: [Bypass007/Nessus_to_report](https://github.com/Bypass007/Nessus_to_report)

主要是想升级到python3，没想到中文编码好多坑。
