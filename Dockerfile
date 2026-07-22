FROM ubuntu:20.04 as builder

# 复制源码到容器
COPY ntripcaster /ntripcaster
WORKDIR /ntripcaster

# 更新源并安装全套编译依赖：gcc、make、autoconf、pkg-config等configure必备组件
RUN apt-get update \
    && apt-get install -y build-essential autoconf automake libtool pkg-config \
    && rm -rf /var/lib/apt/lists/*

# 核心修复：赋予configure及相关脚本执行权限，解决exit code 126权限报错
RUN chmod +x ./configure autogen.sh 2>/dev/null || true
# 如果需要autogen.sh生成configure则取消下面这行注释
# RUN ./autogen.sh

# 编译安装流程
RUN ./configure
RUN make -j$(nproc)
RUN make install

# 第二阶段：精简运行镜像，只拷贝编译产物，减小镜像体积
FROM ubuntu:20.04

# 从构建阶段拷贝安装好的程序
COPY --from=builder /usr/local/ntripcaster/ /usr/local/ntripcaster/

# 暴露服务端口
EXPOSE 2101
WORKDIR /usr/local/ntripcaster/logs
# 配置持久化挂载目录
VOLUME /etc/ntripcaster
# 启动命令
CMD [ "/usr/local/ntripcaster/sbin/ntripdaemon", "-d", "/etc/ntripcaster" ]
