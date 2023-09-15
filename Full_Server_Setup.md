# Provision Ubuntu Server 
I used 22.04.3 Live Server

# Update Server
```bash
sudo apt update && sudo apt upgrade -y && sudo reboot
```

# Add this to bottom of ~/.bashrc 
(run `source ~/.bashrc` after tweaking)
```bash
alias c="clear"

alias compileopenssl='cd /home/$USER/openssl && ./Configure -d --prefix=/usr/local/openssl-3.2 shared && export LD_LIBRARY_PATH="/home/$USER/openssl/" && make && sudo make install && openssl version'

alias testopenssl="./apps/openssl s_server -key ../key.pem -cert ../cert.pem -accept 4443 -state"

alias compilenginx='cd /home/$USER/byu-sandianl-nginx/ && ./auto/configure --with-openssl=/home/$USER/openssl --prefix=/etc/nginx --with-cc-opt="-O3 -fPIE -fstack-protector-strong -Wformat -Werror=format-security" --with-ld-opt="-Wl,-Bsymbolic-functions -Wl,-z,relro" --with-openssl-opt="no-weak-ssl-ciphers no-ssl3 no-shared $ecflag -DOPENSSL_NO_HEARTBEATS -fstack-protector-strong" --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib/nginx/modules --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --pid-path=/var/run/nginx.pid--lock-path=/var/run/nginx.lock --http-client-body-temp-path=/var/cache/nginx/client_temp --http-proxy-temp-path=/var/cache/nginx/proxy_temp --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp --http-scgi-temp-path=/var/cache/nginx/scgi_temp --user=nginx --group=nginx --with-file-aio --with-http_auth_request_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_mp4_module --with-http_realip_module --with-http_secure_link_module --with-http_slice_module --with-http_ssl_module --with-http_stub_status_module --with-http_sub_module --with-http_v2_module --with-pcre-jit --with-stream --with-stream_ssl_module --with-threads --without-http_empty_gif_module --without-http_geo_module --without-http_split_clients_module --without-http_ssi_module --without-mail_imap_module --without-mail_pop3_module --without-mail_smtp_module --with-debug && make'

alias compileapache='cd /home/$USER/byu-sandianl-apache && sudo /sbin/ldconfig -v /usr/local/openssl-3.2/lib64 && LDFLAGS=-L/usr/local/openssl-3.2/lib64 ./configure --with-ssl=/usr/local/openssl-3.2/lib64 --enable-ssl-staticlib-deps --enable-mods-static=ssl && make && sudo /sbin/ldconfig -v /usr/local/openssl/lib64'
```

# Prepare System
```bash
source ~/.bashrc

sudo apt install gcc make libpcre3 libpcre3-dev zlib1g zlib1g-dev libssl-dev subversion autoconf libtool-bin nginx-full
# at this point, nginx should be reachable on port 80
sudo snap install core; sudo snap refresh core
sudo snap install --classic certbot

cd ~/ && git clone https://github.com/openssl/openssl

cd ~/ && git clone https://github.com/christensenjairus/byu-sandianl-nginx

cd ~/ && git clone https://github.com/christensenjairus/byu-sandianl-apache.git

cd ~/ && git clone https://github.com/christensenjairus/byu-sandianl-tls-rtt-packages.git
```

# Compile Openssl
```bash
# Create testing cert
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes

compileopenssl

cd ~/openssl/ && testopenssl
# Visit https://<ip>:4443 to test
```

# Compile & Install Nginx
Nginx is installed as if it were installed by the system. We only replace the binary file, leaving everything how the system left it from the apt install.
```bash
sudo ufw disable
sudo mkdir -p /var/cache/nginx
sudo vim /etc/nginx/nginx.conf
# comment out line 4 that includes modules folder

compilenginx
sudo systemctl stop nginx && cd ~/byu-sandianl-nginx && sudo cp ./objs/nginx $(which nginx) && sudo systemctl start nginx
```

# Setup NGINX with HTTPS Site
```bash
# Update global DNS (in my case, Cloudflare) to point domain to your home IP
# (temporarily) Port forward 80 to this server

sudo certbot --nginx -d example.com

# Remove port-forward

# Test https website on port 443 using hostname

sudo vim /etc/nginx/sites-enabled/default
# Edit ports 443 to be 65535. Comment out server code for port 80.

sudo systemctl restart nginx

# port-forward port 65535
# Test port 65535 using global hostname. Test global connectivity

sudo tail -f /var/log/nginx/access.log

# This will show normal logs, but not new statistic. Lets add that direction for that.

sudo vim /etc/nginx/nginx.conf
# Paste this blob under ## Logging Settings ##

log_format combined_ssl '$remote_addr - $remote_user [$time_local] '
                       # '$ssl_protocol/$ssl_cipher '
                       # '"$request" $status $body_bytes_sent '
                       # '"$http_referer" "$http_user_agent"' 
			'$ssl_protocol/$ssl_cipher w/ $ssl_rtt (tls) and $tcpinfo_rtt (tcp) RTT '
			'"$request" $status';
			
access_log /var/log/nginx/access.log combined_ssl;

# Ensure old access_log line is commented out

sudo systemctl restart nginx

sudo tail -f /var/log/nginx/access.log

# This will now show a custom log format showing TLS and TCP RTTs

# Test with a VPN on. Try a VPN with OpenVPN instead of WireGuard. 
```

# Setup Nginx POC Website
```bash
sudo cp -r ~/byu-sandianl-tls-rtt-packages/Website-For-Nginx/* /var/www/html/
sudo rm /var/www/html/nginx_website.conf

sudo vim /etc/nginx/sites-enabled/default

# Add the following lines to the main server{} block for the SSL port

    sub_filter 'ssl_test' $ssl_rtt;
    sub_filter 'tcp_test' $tcpinfo_rtt;
    sub_filter 'address_ip' $remote_addr;
    sub_filter_types "text/javascript" "application/javascript";
	
# Then restart nginx
sudo systemctl restart nginx

# Visit Website
```

# Make way for Apache
```bash
sudo mkdir /var/www/html/nginx
cd /var/www/html/ && sudo mv ./index.html index.nginx-debian.html js ./nginx

sudo vim /etc/nginx/sites-enabled/default
# change root to be /var/www/html/nginx;

sudo systemctl restart nginx

# Test website to ensure it has not changed functionality
```

# Setup Apache2
Unlike NGINX, Apache will end up being installed very differently in the end. We'll use the apt version to get the certificates and virtualhost config right, then switch to the compiled version's folder (/usr/local/apache/). The apt-installed apache files in /etc/apache2 don't matter once the new instance is set up.
```bash
sudo apt install apache2

# Verify webpage works on port 80 with the IP address

# May need to port-forward again for this, but not if you piggyback on the existing nginx cert 
sudo certbot --apache -d example.com
# (use existing cert and reinstall - option 1)

# Verify the hostname works with local dns hostname and port 443
```

# Replace Apache Version
```bash
cd ~/byu-sandianl-apache && svn co http://svn.apache.org/repos/asf/apr/apr/trunk srclib/apr

# Next blob is direction from here: https://askubuntu.com/questions/679228/error-while-building-apache
# Also, version below will probably be wrong

cd ~/ && apt-get download libexpat1-dev && ar x libexpat1-dev_2.4.7-1ubuntu0.2_amd64.deb && tar --use-compress-program=unzstd -xvf data.tar.zst && cd ~/usr && sudo find . -name expat*.h -exec cp {} /usr/include/ \; && sudo find . -name libexpat.so -exec cp {} /usr/lib/ \; && cd ~/ && rm -r ./usr ./data.tar.zst ./control.tar.zst ./debian-binary ./libexpat1-dev_2.4.7-1ubuntu0.2_amd64.deb

# Prepare enviornment
cd ~/byu-sandianl-apache && ./buildconf

# Compile Apache
compileapache

# Install to System
sudo systemctl disable --now apache2
sudo make install

# Move index.html to new webroot
sudo mv /var/www/html/index.html /usr/local/apache2/htdocs

# Edit new config to allow https
sudo vim /usr/local/apache2/conf/httpd.conf
# Comment out 'Listen 80'
# Add the following to the bottom of the file
<IfModule ssl_module> 
        Listen 65534
</IfModule> 
Include vhost.d/*.conf

# Create new vhost directory
sudo mkdir -p /usr/local/apache2/vhost.d/

# Move applicable files to new location (/usr/local/apache2)
sudo cp /etc/apache2/sites-enabled/000-default-le-ssl.conf /usr/local/apache2/vhost.d/

# Edit vhosts file
sudo vim /usr/local/apache2/vhost.d/000-default-le-ssl.conf
# Change port from 443 to 65534
# Change DocumentRoot to /usr/local/apache2/htdocs
# Add the following line to the top of the file as well
DEFINE APACHE_LOG_DIR /usr/local/apache2/logs

# Start new apache2 instance

sudo killall apache2; sudo /usr/local/apache2/bin/apachectl restart

# Verify that webpage now works again on port 443

sudo tail -f /usr/local/apache2/logs/access.log

# These are the normal logs. Lets get the tls rtt in there now.

sudo vim /usr/local/apache2/conf/httpd.conf
# Edit the 'combined' LogFormat to read the following

LogFormat "%h %l %u %t %{SSL_PROTOCOL}x/%{SSL_CIPHER}x w/ %{SSL_RTT}x (tls) RTT \"%r\" %>s %b" combined

# Exit and restart apache2

sudo killall apache2; sudo /usr/local/apache2/bin/apachectl restart

# View logs

sudo tail -f /usr/local/apache2/logs/access.log
