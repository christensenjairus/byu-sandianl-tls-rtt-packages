# POC Packages for Webserver TLS-Based Proxy Detection.
### BYU &amp; Sandia National Labs Capstone Project
Debian packages for Nginx and Apache with the custom (included) OpenSSL packages. ***These are all modified to calculate and provide the retrieval of TLS round trip time and log it in webserver access logs.***

*NOTE: This is a Proof of Concept and is not recommended for use in production environments. With some luck, this functionality will be released soon built-in to OpenSSL, Nginx, and Apache. Until then, this is recommended for testing only`.*

This SSL/TLS Round Trip Time (RTT) is useful on both the client and server side to detect if a proxy is in use. Various methods like the HTTP RTT and pinging the host can show how long the TLS RTT 'should' be. If the TLS RTT varies too much from this value, there is likely a proxy in use. This can be used to set webserver access rules or firewall rules to react to a proxied connection. 

This solution currently only logs the TLS RTT in the webserver access logs, leaving the blocking/redirection actions to be done by an external program of your choice.

### Webserver access.log example:
![image](https://user-images.githubusercontent.com/58751387/215528725-15a2655d-48e0-406a-b201-fee28c5bed7a.png)

# Installation
### OpenSSL
**Must install this before trying to install either Nginx or Apache, as this is a dependency, and its API has been modified to include a function called `SSL_get_rtt()` that will return the TLS RTT for a given connection.**
1. Clone this repository.
2. Move into the OpenSSL folder with `cd OpenSSL`.
3. To install, run `sudo dpkg -i *.deb` to install all the .deb files in the folder.
4. You may now install Nginx and/or Apache now that you have the new `SSL_get_rtt()` function installed in OpenSSL.

### Nginx and Apache
1. Clone this repository
2. (**APACHE ONLY**) Install a couple needed dependencies with `sudo apt install libapr1-dev libaprutil-dev`.
3. Move into the Nginx or Apache folder with `cd Nginx` or `cd Apache` depending on which you'd like to install.
4. To install, run `sudo dpkg -i *.deb` to install all the .deb files in the folder.
5. (**APACHE ONLY**) Enable the SSL module with `sudo a2enmod ssl && sudo systemctl restart apache2`.
6. Set up Apache or Nginx as normal.

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

# Overview of Our Changes
### OpenSSL
We've modified the state machine of a TLS handshake to create two `OSSL_TIME`s variables at points in the handshake when a round trip should have taken place. This records two timestamps in the form of `ticks`. The difference in these timestamps (titled `rtt`) represents the round trip time for the TLS connection and is stored in the `SSL_Connection` object.

Nginx and Apache use the `SSL` or `SSL_Connection` objects to log data about an SSL connection. The webservers (which call OpenSSL's functions directly), pass in the `SSL` object to OpenSSL functions like `SSL_get_protocol()` and `SSL_get_ciphers()` then log the result. 

We've added a function entitled `SSL_get_rtt()` that the webservers can call to retrieve the rtt for an `SSL` object, allowing them to log the result (which is in microseconds).

Our [patch file](https://github.com/christensenjairus/byu-sandianl-tls-rtt-packages/blob/master/Patch%20Files/add_tls_rtt_openssl.patch) for OpenSSL is relatively jury-rigged compared to our formal branch of OpenSSL, found [here]([https://github.com/christensenjairus/byu-sandianl-openssl](https://github.com/christensenjairus/byu-sandianl-openssl/tree/relocate_rtt)). The reason for this, is that OpenSSL has had a relatively major refactor since the latest Debian version (3.0.5 as of now), preventing us from calling some of their newer functions in this POC. Our patch file has some of these newer functions pasted in and modified. However, after we have our pull request approved, the `SSL_get_rtt()` function will be mainstream and the need for jury-rigging the Debian release may not be necessary for much longer.

The files changed in our formal submission to OpenSSL are `include/openssl/ssl.h.in`, `ssl/ssl_lib.c`, `ssl/ssl_local.h`, `ssl/statem/statem_srvr.c`, and `util/libssl.num`. 

### Nginx
We've added the necessary changes in `src/event/ngx_event_openssl.h`, `src/event/ngx_event_openssl.c`, and `src/http/modules/ngx_http_ssl_module.c` to print the TLS round trip time in microseconds using OpenSSL's new `SSL_get_rtt()` function. This will print out the RTT when the string `$ssl_rtt` is placed in the Nginx logging configuration. These changes can be seen in our [patch file](https://github.com/christensenjairus/byu-sandianl-tls-rtt-packages/blob/master/Patch%20Files/add_tls_rtt_nginx.patch) and in our cloned [repository for Nginx](https://github.com/christensenjairus/byu-sandianl-nginx/tree/add_rtt_timing).

### Apache2
We've added the necessary changes to `/modules/ssl/ssl_engine_kernel.c` and `/modules/ssl/ssl_engine_vars.c` to print the TLS round trip time in microsecondss using OpenSSL's new `SSL_get_rtt()` function. This will print out the RTT when the string `%{SSL_RTT}x` is placed in the Apache logging configuration. These changes can be seen in our [patch file](https://github.com/christensenjairus/byu-sandianl-tls-rtt-packages/blob/master/Patch%20Files/add_tls_rtt_apache.patch). We still need to place these changes in a seperate repository for Apache to review, but hopefully (given the simplicity of this change) Apache developers may just do this work for us once the OpenSSL pull request is accepted.
