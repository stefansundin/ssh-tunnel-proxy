#!/usr/bin/env ruby
require "socket"
require "net/ssh"
require "net/ssh/proxy/jump"

tunnels = [
  {
    local_interface: "127.0.0.1", # This tunnel only accepts connections from your own computer
    local_port: 8881,
    remote_host: "127.0.0.1",
    remote_port: 8880,
    user: "my_username",
    host: "dev1.example.com",
    proxy_jump: "my_username@bastion.example.com",
  },
  {
    local_interface: nil, # This tunnel accepts connections on all interfaces
    local_port: 8882,
    remote_host: "127.0.0.1",
    remote_port: 8880,
    user: "my_username",
    host: "dev2.example.com",
    proxy_jump: "my_username@bastion.example.com",
  },
]

run_ssh_thread = true

tunnels.each do |tunnel|
  proxy = Net::SSH::Proxy::Jump.new(tunnel[:proxy_jump])
  tunnel[:ssh] = Net::SSH.start(tunnel[:host], tunnel[:user], proxy: proxy)
  tunnel[:forwarded_port] = tunnel[:ssh].forward.local(0, tunnel[:remote_host], tunnel[:remote_port])
  puts "Opened SSH connection to #{tunnel[:proxy_jump]} -> #{tunnel[:host]}:#{tunnel[:remote_port]} with ephemeral port #{tunnel[:forwarded_port]}"

  tunnel[:thread] = Thread.new do
    while run_ssh_thread do
      tunnel[:ssh].process(0.01)
      Thread.pass
    end
  end

  tunnel[:server_socket] = TCPServer.new(tunnel[:local_interface], tunnel[:local_port])
  tunnel[:server_socket].listen(128)
  tunnel[:conns] = []
end

loop do
  sockets = tunnels.map { |t| [t[:server_socket], t[:conns]] }.flatten
  result = IO.select(sockets)
  result[0].each do |sock|
    tunnels.each do |tunnel|
      if sock == tunnel[:server_socket]
        client_socket = tunnel[:server_socket].accept
        upstream_socket = TCPSocket.new("localhost", tunnel[:forwarded_port])
        tunnel[:conns].push([client_socket, upstream_socket])
        puts
        puts "New connection to #{tunnel[:proxy_jump]} -> #{tunnel[:host]}:#{tunnel[:remote_port]}"
      end
      tunnel[:conns].each do |conn|
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
          tunnel[:conns].delete(conn)
          puts "!"
          break
        end
      end
    end
  end
end

run_ssh_thread = false
tunnels.each do |tunnel|
  tunnel[:server_socket].close
  tunnel[:thread].join
end
