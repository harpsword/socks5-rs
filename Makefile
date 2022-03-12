
test_socks:
	curl --socks5 127.0.0.1:8999 http://google.com

socks5_user:
	curl --socks5 127.0.0.1:8999 --proxy-user 1234:414 http://google.com