FROM adoptopenjdk/openjdk14:x86_64-ubuntu-jre-14.0.2_12

COPY . /app
WORKDIR /app
ENV LANG C.UTF-8
ENV TZ=Asia/Shanghai
EXPOSE 8080
RUN set -eux; \
    chmod +x /app/sBid; \
    ln -snf /usr/share/zoneinfo/$TZ /etc/localtime; \
    echo $TZ > /etc/timezone
CMD java -jar ./MaskBidClient-1.0.jar --server.port=8080