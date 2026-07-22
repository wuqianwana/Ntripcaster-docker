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
# 设置北京时间时区，日志、时间统一为国内时区
RUN ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

# 拷贝编译好的程序
COPY --from=builder /usr/local/ntripcaster/ /usr/local/ntripcaster/

# 对外服务端口
EXPOSE 2101
# 日志工作目录
WORKDIR /usr/local/ntripcaster/logs
# 配置持久化目录
VOLUME /etc/ntripcaster
# 启动命令和你原有逻辑保持一致
CMD [ "/usr/local/ntripcaster/sbin/ntripdaemon", "-d", "/etc/ntripcaster" ]
