# Webserver TLS-Based Proxy Detection
### POC Debian Packages and Test Website
##### BYU &amp; Sandia National Labs Capstone Project
Debian packages for OpenSSL, Nginx and Apache. ***These are all modified to calculate and provide the retrieval of TLS handshake round trip time and log it in webserver access logs.*** The OpenSSL changes could be used for other applications (e.g. SSH).

*NOTE: This is a Proof of Concept and is not recommended for use in production environments. This functionality will be released soon built-in to OpenSSL, Nginx, and Apache (see our pending pull request). Until then, this is recommended for testing only. Ubuntu 22.10 was used to create these packages*

This SSL/TLS Handshake Round Trip Time (RTT) is useful on both the client and server side to detect if a proxy is in use. 

This is an important metric for protecting assets like webservers from attackers that are using proxies. This includes
   * Commercial VPNs
   * Privately set up proxies that would otherwise trick IP Reputation techniques
   * Compromised IoT devices

Various methods like the HTTP RTT and pinging the host can show how long the TLS Handshake RTT *should* be. If the TLS RTT varies too much from this value, there is likely a proxy in use. This can be used to set webserver access rules or firewall rules to react to a proxied connection.

Webserver logic can be introduced using the combination of the TLS, TCP, and Ping RTTs to block or redirect a client that may be using a proxy.

### Webserver access.log example:
![image](https://user-images.githubusercontent.com/58751387/215528725-15a2655d-48e0-406a-b201-fee28c5bed7a.png)

# Methodology to Detect a Proxy
### No Proxy
Let's say we have a webserver that is accepting network connections. For a non-proxied connection, the TCP RTT, TLS/SSL RTT, and the ping time will be very similar. The screenshot below illustrates this example. The webserver sees that the connection's TCP RTT, TLS RTT, and ping time (**44ms**) are within a couple milliseconds (or few thousand microseconds) of each other. 

In non-proxied connections, ***there is not a large discrepency between the TCP, TLS and ping RTTs.***

TCP vs TLS RTT with no Proxy:

![image](https://user-images.githubusercontent.com/58751387/217104156-f67f34fd-812f-4acf-a364-a5277f9be749.png)

### TCP Proxy
However, if we introduce a **TCP-based** proxy (located only a few hundred miles away), the TCP RTT value will now be different the TLS RTT value and both of thsee will be more than the ping time of **23ms**. This is because the TCP connection is terminated at the proxy, but the TLS connection is end-to-end, back to the client. Also, TCP proxies are very slow in comparison to other types. For this reason, both TCP and TLS RTTs will be much higher than the ping time. ***The discrepency between the TCP and TLS RTT gives away that this is a proxy.***

TCP vs TLS RTT with TCP-based Proxy:

![image](https://user-images.githubusercontent.com/58751387/217106797-93cfb655-5503-461f-9a3b-f2060145b8d3.png)

### UDP Proxy
When using a **UDP-based proxy** located in the same geographical area as the TCP-based proxy, the TCP RTT value will now match the TLS RTT and both will continue to be more than the ping time of **23ms**. In this case, TCP and TLS are end-to-end. ***The discrepency between those RTT values and the ping time gives away that this is a proxy.***

TCP vs TLS RTT with UDP Proxy:

![image](https://user-images.githubusercontent.com/58751387/217106201-a0798dd1-567c-46f7-a17d-8c17d0c76cbc.png)

### Tor
Tor is the easiest of all these proxies to detect because the ping time (**28ms**) and the TCP RTT are much, much less than from the TLS RTT. ***The discrepency between the TCP & Ping RTT and the TLS RTT gives away that this is a proxy.***

TCP vs TLS RTT with Tor:

![image](https://user-images.githubusercontent.com/58751387/217109527-632fbab3-2956-4dd1-ad83-2dd8432e85ae.png)

### Other proxies
We will be experminenting with other proxy types to see if we can fool this methodology. 

We're aware of at least one scenario in which TLS timing analysis can be fooled: if a proxy were to terminate the TLS and TCP connections instead of forwarding the existing connection on to the client. If this is done, there will be separate TLS and TCP connections between the client & proxy and the proxy & server. Most attackers would not want to terminate the TLS connection because their actions would be visible on the proxy (the data would have to be plain text at some point while it goes from one TLS connection to another). An attacker would have to trust this proxy completely in order to feel comfortable with this. If this is the case, and IP reputation doesn't help detect a proxy, an attacker's proxy could avoid being detected.

# Installation
### Update
Updating might go without saying, however, *these are the latest packages Debian stable has to offer* (as of the beginning of Feb 2023), and some of them *may be dependant on newer versions of other programs* like `perl`.
```bash
sudo apt-get update && sudo apt-get upgrade -y
```
### OpenSSL
**You must install this before installing either Nginx or Apache as this is a dependency and its API has been modified to include a function called `SSL_get_handshake_rtt()` that will return the TLS Handshake RTT for a given connection.**
1. Clone this repository.
2. Move into the OpenSSL folder with `cd OpenSSL`.
3. To install, run `sudo dpkg -i *.deb` to install all the .deb files in the folder.
4. You may now install Nginx and/or Apache now that you have the new `SSL_get_handshake_rtt()` function installed in OpenSSL.

### Nginx and Apache
1. Clone this repository
2. Install a couple needed dependencies with `sudo apt install libpcre2-dev debhelper`
3. (**APACHE ONLY**) Install a couple needed dependencies with `sudo apt install libapr1-dev libaprutil-dev`.
4. Move into the Nginx or Apache folder with `cd Nginx` or `cd Apache` depending on which you'd like to install.
5. To install, run `sudo dpkg -i *.deb` to install all the .deb files in the folder.
    * If this fails, try `sudo apt --fix-broken install` and then try again.
    * (**NGINX ONLY**) You may need to install the `nginx-core` package first so the other packages know its already installed and don't complain
    * Note: We've placed `nginx-light` nor `nginx-extras` in the `extras` folder because they conflict with `nginx-core`. If you want those packages instead of `nginx-core`, just install the ones you want/need.
6. (**APACHE ONLY**) Enable the SSL module with `sudo a2enmod ssl && sudo systemctl restart apache2`.
7. Set up Apache or Nginx as normal.

# Logging the SSL RTT
### Nginx
1. Open the `/etc/nginx/nginx.conf` file (or whereever your logging configuration file is)
2. Add the logging variable `$ssl_rtt` to the log configuration. 
    * You may need to add a logging configuration like this one if you haven't done so already. Remember to add the name of the logging configuration on the `access_log` line so your log configuration format is used in `access.log`.

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
6. You may need to run `sudo dpkg -i *.deb` in the `OpenSSL` folder again if you're not recieving any output for the RTT. The `sudo apt --fix-broken install` command from earlier might have replaced our version of `libssl` or `openssl` and you don't want that.

# Running the Website
##### (Nginx-Specific)
We've created a simple configuration to expose Nginx's logging variables by injecting them into the webpage and performing logic via javascript. Ideally, this would be done on the server end via a server-side scripting language like PHP. Or even better, as an Nginx module that could block the connection before the contents of the request are returned to the client. Our simple webpage, however, is simply a POC that helps you verify that the server is running correctly and aids in testing various VPN types and seeing their respective RTT values.

The webpage will appear green when a proxy is not detected:

![Non-Proxied Connection](https://user-images.githubusercontent.com/58751387/232553496-dbcf395e-de46-4a0b-be3b-b9945378a53c.png)

Or red when a proxy is detected:

![Proxied Connection](https://user-images.githubusercontent.com/58751387/232553602-6f103a21-e856-4a94-870b-bd87c6cbb9c6.png)

**Note:** The algorithm used in this POC website needs to be tuned. Currently, the website is using simple logic that is functionaly equivalent to the code below:
```c
if ((TLS_RTT - 20ms) > TCP_RTT) {
     proxy;
} else {
     not proxy;
}
```
With more research on what real-world & in-the-wild proxies look like as far as variance, the above function can be tuned. 

Future research will determine
* if using a ratio of the TLS/TCP is a better route for proxy detection (i.e. block everything where the TLS RTT is >150% of the TCP RTT),
* if incorporating the ping is absolutely necessary to detect some proxy types,
* the best route to fingerprint clients on the server side across many connections using this metric, and
* how many samples of TLS RTT & TCP RTT are necessary to create reliable averages.

### Installation:
* Place `index.html` and the `js` folder in the web root. Your webroot could be `/var/www/html/`
* Edit your nginx website configuration to use the `sub_filter` and `subfilter_types` lines from `nginx_website.conf`
* Reload nginx with `sudo systemctl restart nginx`

# Overview of Our Changes
### OpenSSL
We've modified the state machine of a TLS handshake to create two `OSSL_TIME`s variables at points in the handshake when a round trip should have taken place. This records two timestamps in the form of `ticks`. The difference in these timestamps (titled `handshake_rtt`) represents the round trip time for the TLS connection and is stored in the `SSL_Connection` object.

Nginx and Apache use the `SSL` or `SSL_Connection` objects to retrieve data about an SSL connection. The webservers (which call OpenSSL's functions directly), pass in the `SSL` object to OpenSSL functions like `SSL_get_protocol()` and `SSL_get_ciphers()` then log the result. 

We've added a function entitled `SSL_get_handshake_rtt()` that the webservers can call to retrieve the handshake rtt for an `SSL` object, allowing them to log the result (which is in microseconds).

Our [patch file](https://github.com/christensenjairus/byu-sandianl-tls-rtt-packages/blob/master/Patch%20Files/add_tls_rtt_openssl.patch) for OpenSSL is inferior to our formal branch of OpenSSL, found [here](https://github.com/christensenjairus/byu-sandianl-openssl/tree/relocate_rtt). The reason for this is that OpenSSL has had a relatively major refactor since the latest Debian version (3.0.5 as of now), preventing us from calling some of their newer functions in this POC. Our patch file has some of these newer functions pasted in and modified. However, after we have our pull request approved, the `SSL_get_handshake_rtt()` function will be mainstream and the need for our patch file may not be necessary for much longer.

The files changed in our formal submission to OpenSSL are `include/openssl/ssl.h.in`, `ssl/ssl_lib.c`, `ssl/ssl_local.h`,`ssl/statem/statem_srvr.c`, `ssl/statem/statem_clnt.c`, and `util/libssl.num`. 

### Nginx
We've added the necessary changes in `src/event/ngx_event_openssl.h`, `src/event/ngx_event_openssl.c`, and `src/http/modules/ngx_http_ssl_module.c` to print the TLS handshake round trip time in microseconds using OpenSSL's new `SSL_get_handshake_rtt()` function. This will print out the handshake RTT when the string `$ssl_rtt` is placed in the Nginx logging configuration. These changes can be seen in our [patch file](https://github.com/christensenjairus/byu-sandianl-tls-rtt-packages/blob/master/Patch%20Files/add_tls_rtt_nginx.patch) and in our cloned [repository for Nginx](https://github.com/christensenjairus/byu-sandianl-nginx/tree/relocate_rtt).

### Apache2
We've added the necessary changes to `/modules/ssl/ssl_engine_kernel.c` and `/modules/ssl/ssl_engine_vars.c` to print the TLS round trip time in microseconds using OpenSSL's new `SSL_get_handshake_rtt()` function. This will print out the RTT when the string `%{SSL_RTT}x` is placed in the Apache logging configuration. These changes can be seen in our [patch file](https://github.com/christensenjairus/byu-sandianl-tls-rtt-packages/blob/master/Patch%20Files/add_tls_rtt_apache.patch). We still need to place these changes in a seperate repository for Apache to review, but hopefully (given the simplicity of this change) Apache developers may just do this work for us once the OpenSSL pull request is accepted.

## To Do:
- [X] Client-side TLS RTT calculation for TLS 1.2 connections
- [X] Client-side TLS RTT calculation for TLS 1.3 connections
- [X] Refactor NGINX, Apache, and OpenSSL to use `uint64_t` return data type for `SSL_get_handshake_rtt()`
- [X] Rename functions/variables/comments to be `handshake_rtt` instead of just `rtt` to be more clear on what this value really is
- [ ] Complete Pull Request for OpenSSL
- [ ] Complete Pull Request for Nginx
- [ ] Complete Pull Request for Apache
