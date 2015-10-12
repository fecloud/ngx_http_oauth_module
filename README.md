# ngx_http_oauth_module

./configure  --prefix=/home/dev/nginx-release --with-pcre=../pcre-8.35 --with-zlib=../zlib-1.2.8 --add-module=../ngx_http_oauth_module


admin:$apr1$bSMiryUi$0XkIpfnuRqbwjziuWxI.v/

oauth "oauth";
oauth_user_file /home/dev/htpasswd;


wget -v -d --http-user=admin --http-password=ouyangfeng http://192.168.159.128