FROM ubuntu:20.04 as builder
# 关闭apt交互式弹窗，解决tzdata时区选择卡死问题
ENV DEBIAN_FRONTEND=noninteractive

COPY ntripcaster /ntripcaster
WORKDIR /ntripcaster

# 安装全套编译依赖，清理缓存减小构建体积
RUN apt-get update \
    && apt-get install -y build-essential autoconf automake libtool pkg-config \
    && rm -rf /var/lib/apt/lists/*

# 赋予configure执行权限，修复exit code 126权限报错
RUN chmod +x ./configure autogen.sh 2>/dev/null || true
# 若源码需要autogen.sh生成configure，取消下行注释
# RUN ./autogen.sh

RUN ./configure
RUN make -j$(nproc)
RUN make install

# 运行镜像阶段
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Asia/Shanghai
# 安装时区数据文件，保证zoneinfo目录存在，软链接可生效
RUN apt-get update \
    && apt-get install -y tzdata \
    && rm -rf /var/lib/apt/lists/*
# 设置系统时区为北京时间，适配直接读取/etc/localtime的ntripcaster程序
RUN ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

# 拷贝编译好的程序
COPY --from=builder /usr/local/ntripcaster/ /usr/local/ntripcaster/

# 对外服务端口
EXPOSE 2101
# 日志工作目录
WORKDIR /usr/local/ntripcaster/logs
# 配置持久化目录
VOLUME /etc/ntripcaster
# 启动命令和原有逻辑保持一致
CMD [ "/usr/local/ntripcaster/sbin/ntripdaemon", "-d", "/etc/ntripcaster" ]
