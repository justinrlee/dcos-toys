FROM nginx:1.12.1-alpine
RUN apk add openssl

RUN mkdir -p /etc/nginx/ssl && \
    openssl req -x509 \
    -nodes \
    -days 365 \
    -newkey rsa:2048 \
    -subj '/C=US/ST=CA/L=San Francisco/O=Mesosphere/CN=localhost'\
    -keyout /etc/nginx/ssl/nginx.key -out /etc/nginx/ssl/nginx.crt

COPY secure.conf /etc/nginx/conf.d/