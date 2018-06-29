FROM nginx:1.15.0

RUN apt-get update -y \
  && apt-get install -y --no-install-recommends \
    iputils-ping \
    curl \
    wget \
    ca-certificates \
    procps \
    iproute2

RUN wget https://download.splunk.com/products/universalforwarder/releases/7.1.1/linux/splunkforwarder-7.1.1-8f0ead9ec3db-Linux-x86_64.tgz -O /tmp/splunkforwarder.tgz

RUN tar -xzvf /tmp/splunkforwarder.tgz -C /opt/ \
  && rm /tmp/splunkforwarder.tgz

COPY user-seed.conf /opt/splunkforwarder/etc/system/local

COPY entrypoint.sh /

ENTRYPOINT ["/entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
