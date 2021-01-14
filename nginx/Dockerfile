FROM nginx
RUN apt update
RUN apt install nginx-extras -y
RUN rm /etc/nginx/conf.d/default.conf
COPY nginx.conf /etc/nginx/conf.d
RUN openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
    -subj "/C=PL/ST=mazowieckie/L=Warszawa/O=cos/CN=tam" \
    -keyout host.key  -out host.cert