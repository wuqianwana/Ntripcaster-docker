# Ntripcaster-docker
此项目是由BGK开源NTRIP Caster在Docker下运行

目前使用的BKG-Ntripcaster版本为2.0.47（2025-01-07）

该存储库包含在 docker 下运行的 BKG NTRIP 播发器。

NTRIP 由德国联邦制图和大地测量局 (BKG) 发明。它用于通过互联网将 GNSS 基站的校正数据传输到 GNSS 流动站。（GNSS 是我们通常所说的 GPS 的统称。）

BKG使用说明书网址https://igs.bkg.bund.de/root_ftp/NTRIP/documentation/ntripcaster_manual.html

## 准备配置
首先你必须在主机上准备一些配置：
```shell
$ wget -O config.sh https://raw.githubusercontent.com/wuqianwana/Ntripcaster-docker/master/config.sh
```

然后：
```shell
$ chmod +x config.sh && ./config.sh
```

然后配置ntripcaster.conf和其他用户或组、sourcetable文件。
```shell
$ vim /etc/ntripcaster/ntripcaster.conf
```

### 编辑 ntripcaster.conf
在施法者元数据中输入您的详细信息
```
location your_location
rp_email your_email@my.domain.com
server_url http://my.domain.com
```
输入 ntrip 服务器将数据推送到 Caster 时使用的密码。无需用户名。
```
encoder_password yourPassword
```
输入施放者的域名，例如，测试时输入 localhost，实际使用时输入 my.domain.com。此域名不能是 IP 地址。选择要使用的端口 - 标准端口为 2101，但您可以使用任何您喜欢的端口。
```
server_name localhost
#port 80
port 2101
```
mountpos 设置用于最近的基准功能。将 `auto_mount` 设置为 `false` 以禁用它。
```
mountposfile /usr/local/ntripcaster/conf/mountpos.conf
auto_mount true
read_gpgga_interval 15
```
挂载点用户名和密码遵循以下格式：只有用户“usera”和密码“abc”或“userb”和密码“def”可以访问“test”。任何用户都可以访问“pub”。请根据个人喜好进行调整。
```
/test:usera:abc,userb:def
/pub
```
### 源表.dat

该文件位于 conf 目录（ntripcaster/ntripcaster/conf）中。您需要根据自己的需要对其进行编辑。

BKG 的说明称：“无论您的“sourcetable.dat”最终的内容是什么，建议在该配置文件中包含以下行：CAS;rtcm-ntrip.org;2101;NtripInfoCaster;BKG;0;DEU;50.12;8.69; http://www.rtcm-ntrip.org/home ”。

该行已在示例源表文件中，因此您可以保留它。

除了第一行之外，sourcetable.dat 还定义了你的挂载点。每个基站都需要一个。我有一个基站，它位于我位于英国莱瑟黑德的棚屋屋顶上。我将我的挂载点命名为“uk_leatherhead”。

sourcetable.dat 的每一行都是一个用分号分隔的字段列表。我的代码如下：
```
CAS;rtcm-ntrip.org;2101;NtripInfoCaster;BKG;0;DEU;50.12;8.69;http://www.rtcm-ntrip.org/home
STR;uk_leatherhead;Leatherhead;RTCM 3.0;;;;;GBR;51.29;-0.32;1;0;sNTRIP;none;N;N;0;;
```

第二行的字段 1 是“STR”，表示它正在定义一个挂载点。

字段 2“uk_leatherhead”是我的挂载点的名称。

3 号场地“莱瑟黑德”是距离我的基站最近的城镇。

RTCM 3.0 意味着 NTRIP 连接正在携带 RTCM 版本 3 消息，这是我的基站生成的消息。

GBR 是英国的三字母代码。您可以 在这里找到您所在国家/地区的两字母和三字母代码。

“51.29;-0.32”给出了我的基站的经度和纬度。如果您没有这些信息，可以使用“0.00;0.00”。


- ntripcaster.conf,   主配置
- clientmounts.aut,   客户端的流身份验证
- sourcemounts.aut,   源的流身份验证（Ntrip 2.0）
- users.aut,          用户定义
- groups.aut,         组定义
- sourcetable.dat,    包含流信息的源表

如果您想使用经过用户和密码验证的流，则需要相应地编辑 .aut 文件。

在这些文件中，您可以找到有关可以指定哪些内容以及如何执行这些操作的帮助。

## 启动容器
下面是启动一个监听 2101 端口的容器的示例，以 ntripcaster 的形式运行，如下所示：
```shell
$ docker run -d -p 2101:2101 --name ntripcaster --restart=always -v /etc/ntripcaster:/etc/ntripcaster rinex20/ntripcaster
```
```shell
docker run -d -p 2101:2101 --restart=always -v /etc/ntripcaster:/etc/ntripcaster ntripcaster
```
