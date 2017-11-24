mkdir -p ssh-tunnel-proxy-0.0.1/usr/bin/
cp ssh-tunnel-proxy/ssh-tunnel-proxy.rb ssh-tunnel-proxy-0.0.1/usr/bin/ssh-tunnel-proxy
dpkg -b ssh-tunnel-proxy-0.0.1
