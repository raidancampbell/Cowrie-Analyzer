# Cowrie-Analyzer
Provides at-a-glance info from the Cowrie honeypot JSON logs 

### Usage
clone this repo, have a subdirectory of Cowrie JSON files in a directory called `log`, and run with python3.
This can be run from the root of the Cowrie folder itself without any configuration or changes.

A sample output can be found below.  Additionally, a simple graph of Telnet and SSH attempts is created and stored in the file `attack_attempts.png`
### Sample Output
```
telnet attempts: 58793
SSH attempts:33545
10 most common source addresses:
('185.107.80.198', 24209)
('185.107.80.199', 14993)
('61.177.172.46', 10669)
('195.22.127.83', 6158)
('149.202.40.182', 2195)
('207.244.78.15', 1694)
('93.174.93.219', 1161)
('208.167.254.97', 1093)
('61.177.172.32', 1063)
('109.201.134.2', 840)
most common username attempts:
('root', 37335)
('sh', 14091)
('enable', 14076)
('admin', 9267)
('enable\\x00', 1890)
('shell\\x00', 1722)
('admin1', 1020)
('support', 743)
('guest', 597)
('user', 468)
('test', 421)
('0000', 419)
('ubnt', 409)
('service', 303)
('usuario', 284)
('master', 248)
('mother', 223)
('administrator', 215)
('supervisor', 205)
('Administrator', 203)
('tech', 188)
('1111', 165)
('pi', 159)
('888888', 157)
('oracle', 157)
('666666', 155)
('tomcat', 145)
('web', 141)
('0', 135)
('mysql', 131)
most common password attempts:
('shell', 14154)
('/bin/busybox ECCHI', 13965)
('admin', 4875)
('xmhdipc', 2135)
('1234', 1971)
('password', 1960)
('system\\x00', 1890)
('12345', 1787)
('sh\\x00', 1722)
('123456', 1529)
('root', 1457)
('', 1333)
('888888', 1322)
('dreambox', 1271)
('anko', 1151)
('juantech', 1103)
('7ujMko0admin', 1103)
('xc3511', 1069)
('vizxv', 1035)
('smcadmin', 891)
('admin1234', 868)
('support', 718)a
('pass', 639)
('0000', 609)
('ubnt', 482)
('1111', 476)
('user', 460)
('00000000', 453)
('openelec', 441)
('default', 396)
most common username/password combos:
('enable:shell', 14044)
('sh:/bin/busybox ECCHI', 13965)
('admin:admin', 2606)
('root:xmhdipc', 2122)
('root:admin', 2100)
('enable\\x00:system\\x00', 1890)
('shell\\x00:sh\\x00', 1722)
('root:root', 1402)
('root:dreambox', 1258)
('root:888888', 1186)
```
### Sample of `attack_attempts.png`
![attack_attempts](https://cloud.githubusercontent.com/assets/5506073/24591054/a49850c4-17ad-11e7-9d41-ab5f0c0e5e41.png)
