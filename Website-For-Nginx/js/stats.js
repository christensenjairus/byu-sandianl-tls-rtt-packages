function myFunction() {
    var ssl_rtt = ssl_test
    var tcp_rtt = tcp_test
    var ip_address = "address_ip"
    if ((ssl_rtt - 20000) > tcp_rtt) {
        document.body.style.backgroundColor = "#C80000"
    }
    else {
        document.body.style.backgroundColor = "green"
    }
    document.getElementById("tcp_rtt").innerHTML = tcp_rtt;
    document.getElementById("ssl_rtt").innerHTML = ssl_rtt;
    document.getElementById("ip_address").innerHTML = ip_address;
    percentage = (ssl_rtt - tcp_rtt)
    document.getElementById("percent").innerHTML = Math.abs(percentage);
}