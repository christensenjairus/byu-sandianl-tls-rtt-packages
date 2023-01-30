# Packages for BYU-Sandia National Labs TLS-Based Proxy Detection.
BYU &amp; Sandia National Labs Capstone Project. Debian packages for Nginx and Apache with the custom (included) OpenSSL packages. These are all modified to calculate and provide the retrieval of TLS round trip time and log it in the webserver access logs.

This SSL/TLS Round Trip Time (RTT) is useful on both the client and server side to detect if a proxy is in use. Various methods like the HTTP RTT and pinging the host can show how long the TLS RTT 'should' be. If the TLS RTT varies too much from this value, there is likely a proxy in use. This can be used to set webserver access rules or firewall rules to react to a proxied connection. 

This solution currently only logs the TLS RTT in the webserver access logs, leaving the blocking/redirection actions to be done by an external program of your choice.

### Webserver access.log example:
![image](https://user-images.githubusercontent.com/58751387/215528725-15a2655d-48e0-406a-b201-fee28c5bed7a.png)

# Installation
1. Clone this repository
2. `cd` into either `Apache2` or `Nginx` depending on which web server you'd like to install
3. `sudo dpkg -i *.deb` to install all the .deb files in the folder
4. Set up Apache or Nginx as normal.

# Logging the SSL RTT
### Nginx
1. Open the `/etc/nginx/nginx.conf` file (or whereever your logging configuration file is)
2. Add the logging variable `$ssl_rtt` to the log configuration.
![image](https://user-images.githubusercontent.com/58751387/215526431-2e12d08c-05e9-4f4c-a7f9-a48060dcd16b.png)
3. Save the file
4. Restart Nginx with `sudo systemctl restart nginx`
5. View the logs with `sudo tail -f /var/log/nginx/access.log` or wherever your log file is located.

### Apache2
1. Open the `/etc/apache2/apache2.conf` file (or whereever your logging configuration file is)
2. Add the logging variable `${SSL_RTT}x` to the log configuration.
![image](https://user-images.githubusercontent.com/58751387/215527575-fb4134fa-85df-4a54-914c-71f4ca2f8131.png)
3. Save the file
4. Restart Nginx with `sudo systemctl restart apach2`
5. View the logs with `sudo tail -f /var/log/apache2/access.log` or wherever your log file is located.

# Overview of our changes
### OpenSSL

### Nginx

### Apache2
