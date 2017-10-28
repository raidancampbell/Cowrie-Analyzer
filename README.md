# Cowrie-Analyzer
Provides at-a-glance info from the Cowrie honeypot JSON logs 

### Usage
clone this repo, have a subdirectory of Cowrie JSON files in a directory called `log`, and run with python3.
This can be run from the root of the Cowrie folder itself without any configuration or changes.

A sample output can be found below.  Additionally, a simple graph of Telnet and SSH attempts is created and stored in the file `attack_attempts.png`
### Sample Output
```
telnet attempts: 395126
SSH attempts:140980
most common source addresses:
('52.27.104.84', 75061)
('52.15.233.30', 65778)
('195.22.127.83', 37419)
('185.107.80.198', 30306)
('185.107.80.199', 22013)
('109.236.83.181', 19688)
('61.177.172.46', 10669)
('109.236.83.229', 9744)
('34.210.4.202', 9219)
('52.36.170.183', 8828)
most common username attempts:
('root', 180029)
('enable', 95611)
('sh', 87370)
('admin', 48885)
('support', 15334)
('shell', 9735)
('enable\\x00', 8450)
('shell\\x00', 8143)
('guest', 6486)
('0000', 3951)
('admin1', 3812)
('user', 2744)
('Administrator', 2627)
('test', 1925)
('service', 1866)
('administrator', 1775)
('ubnt', 1697)
('mother', 1675)
('system', 1586)
('', 1521)
('>/mnt/.ptmx && cd /mnt/', 1496)
('>/boot/.ptmx && cd /boot/', 1496)
('>/bin/.ptmx && cd /bin/', 1496)
('>/dev/netslink/.ptmx && cd /dev/netslink/', 1496)
('>/var/.ptmx && cd /var/', 1496)
('>/var/tmp/.ptmx && cd /var/tmp/', 1496)
('usuario', 1474)
('master', 1192)
('1111', 1189)
('oracle', 1137)
most common password attempts:
('shell', 87381)
('/bin/busybox ECCHI', 85105)
('admin', 28467)
('support', 15259)
('root', 12574)
('', 12395)
('12345', 11857)
('system', 11855)
('password', 11343)
('xc3511', 9978)
('sh', 9766)
('123456', 9449)
('system\\x00', 8454)
('1234', 8433)
('sh\\x00', 8142)
('vizxv', 7769)
('juantech', 7621)
('xmhdipc', 7466)
('888888', 6850)
('anko', 5929)
('0000', 5829)
('pass', 5258)
('admin1234', 4633)
('dreambox', 4397)
('1111', 4301)
('default', 4125)
('7ujMko0admin', 3399)
('user', 3328)
('54321', 3151)
('smcadmin', 3025)
most common username/password combos:
('enable:shell', 85867)
('sh:/bin/busybox ECCHI', 85105)
('support:support', 15169)
('root:admin', 13833)
('admin:admin', 13765)
('root:root', 12241)
('root:xc3511', 9954)
('enable:system', 9744)
('shell:sh', 9730)
('enable\\x00:system\\x00', 8450)
The address 185.203.241.80 is not in the database.
unique source IPs:
30916
unique countries for source IPs:
164
most common countries for source IPs:
('China', 4592)
('Russia', 4020)
('Vietnam', 2194)
('Brazil', 2075)
('United States', 1467)
('Taiwan', 1346)
('Republic of Korea', 1282)
('Turkey', 1228)
('India', 1227)
('Argentina', 976)
unique countries for overall attacks:
164
most common countries for overall attacks:
('United States', 180007)
('Netherlands', 120535)
('China', 44841)
('Poland', 38700)
('Russia', 16409)
('Vietnam', 13423)
('Italy', 9958)
('Argentina', 9232)
('France', 8087)
('Seychelles', 7617)
```
### Sample of `attack_attempts.png`
![attack_attempts](https://user-images.githubusercontent.com/5506073/32137196-e872196c-bbcf-11e7-8a1c-ccf40e85ccfb.png)
