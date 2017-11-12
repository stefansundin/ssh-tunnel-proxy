#!/usr/bin/env ruby
require "socket"
require "net/ssh"
require "net/ssh/proxy/jump"

listen_port = 9090
upstream_port = 8880

host = "example.com"
user = "my_username"
proxy_host = "bastion.example.com"

proxy = Net::SSH::Proxy::Jump.new("#{user}@#{proxy_host}")
ssh = Net::SSH.start(host, user, proxy: proxy)
local_port = ssh.forward.local(0, "127.0.0.1", upstream_port)
puts "ephemeral port: #{local_port} -> #{upstream_port}"

run_ssh_thread = true
ssh_thread = Thread.new do
  while run_ssh_thread do
    ssh.process(0.01)
    Thread.pass
  end
end

open_conns = []
server_socket = TCPServer.new(listen_port)
server_socket.listen(128)
loop do
  read_sockets = [server_socket, open_conns].flatten
  result = IO.select(read_sockets)
  result[0].each do |sock|
    if sock == server_socket
      client_socket = server_socket.accept
      upstream_socket = TCPSocket.new("localhost", local_port)
      open_conns.push([client_socket, upstream_socket])
      puts "/"
    else
      open_conns.each do |conn|
        begin
          if sock == conn[0]
            conn[1].write(conn[0].read_nonblock(4096))
            printf "."
          elsif sock == conn[1]
            conn[0].write(conn[1].read_nonblock(4096))
            printf "."
          end
        rescue EOFError
          conn[0].close
          conn[1].close
          open_conns.delete(conn)
          puts "!"
          break
        end
      end
    end
  end
end
server_socket.close

run_ssh_thread = false
ssh_thread.join
