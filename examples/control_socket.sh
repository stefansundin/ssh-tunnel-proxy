# Dynamically open a new tunnel without having to restart ssh-tunnel-proxy.
# Note that the configuration is NOT persisted across restarts!

cat << EOF | nc -U $HOME/.ssh/ssh-tunnel-proxy.sock
[[tunnel]]
user = "my_username"
host = "dev1.example.com"
[[tunnel.forward]]
type = "local"
local_socket = "~/.ssh/mysql2.sock"
remote_host = "mysql2.service.consul"
remote_port = 3306
EOF
