FROM ubuntu:20.04 as builder
# 全局关闭apt交互式弹窗，彻底解决tzdata时区选择卡住问题
ENV DEBIAN_FRONTEND=noninteractive

COPY ntripcaster /ntripcaster
WORKDIR /ntripcaster

# 安装全套编译依赖，清理apt缓存减小镜像体积
RUN apt-get update \
    && apt-get install -y build-essential autoconf automake libtool pkg-config \
    && rm -rf /var/lib/apt/lists/*

# 赋予configure等脚本执行权限，修复exit code 126权限报错
RUN chmod +x ./configure autogen.sh 2>/dev/null || true
# 若源码需要先执行autogen.sh生成configure，则取消下面注释
# RUN ./autogen.sh

RUN ./configure
RUN make -j$(nproc)
RUN make install

# 精简运行镜像阶段
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
# 如需国内上海时区，启用下面这行
# RUN ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

COPY --from=builder /usr/local/ntripcaster/ /usr/local/ntripcaster/

EXPOSE 2101
WORKDIR /usr/local/ntripcaster/logs
VOLUME /etc/ntripcaster
CMD [ "/usr/local/ntripcaster/sbin/ntripdaemon", "-d", "/etc/ntripcaster" ]
