# Ntripcaster-docker
此项目是由BGK开源NTRIP Caster在Docker下运行

该存储库包含在 docker 下运行的 BKG NTRIP 播发器。

NTRIP 由德国联邦制图和大地测量局 (BKG) 发明。它用于通过互联网将 GNSS 基站的校正数据传输到 GNSS 流动站。（GNSS 是我们通常所说的 GPS 的统称。）

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

- ntripcaster.conf,   main configuration
- clientmounts.aut,   stream authentication for ntrip clients
- sourcemounts.aut,   stream authentication for ntrip sources (Ntrip 2.0)
- users.aut,          user definitions
- groups.aut,        group definitions
- sourcetable.dat,    the sourcetable containing stream information

如果您想使用经过用户和密码验证的流，则需要相应地编辑 .aut 文件。

在这些文件中，您可以找到有关可以指定哪些内容以及如何执行这些操作的帮助。

## 启动容器
下面是启动一个监听 2101 端口的容器的示例，以 ntripcaster 的形式运行，如下所示：
```shell
$ docker run -d -p 2101:2101 --name ntripcaster --restart=always -v /etc/ntripcaster:/etc/ntripcaster rinex20/ntripcaster
```
