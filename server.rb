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

trap("INT") do
  puts "\nBye!"
  run_ssh_thread = false
  tunnels.each do |tunnel|
    tunnel[:thread].join if tunnel[:thread]
    tunnel[:server_socket].close if tunnel[:server_socket] && !tunnel[:server_socket].closed?
  end
  exit
end

tunnels.each do |tunnel|
  tunnel[:server_socket] = TCPServer.new(tunnel[:local_interface], tunnel[:local_port])
  tunnel[:server_socket].listen(128)
  tunnel[:conns] = []
  tunnel[:pending_conns] = []
end

puts "Started listening on ports: #{tunnels.map { |t| t[:local_port] }}"


loop do
  sockets = tunnels.map { |t| [t[:server_socket], t[:conns]] }.flatten
  result = IO.select(sockets, nil, nil, 1) # We have to use a timeout to pick up new connections that were pending
  next if result == nil
  result[0].each do |sock|
    tunnels.each do |tunnel|
      if sock == tunnel[:server_socket]
        printf "/"
        if tunnel[:ssh]
          client_socket = tunnel[:server_socket].accept
          tunnel[:pending_conns].push(client_socket)
        else
          tunnel[:ssh] = true
          puts
          puts "Opening SSH connection to #{tunnel[:host]}:#{tunnel[:remote_port]}#{tunnel[:proxy_jump] ? " (via #{tunnel[:proxy_jump]})":""}..."
          tunnel[:thread] = Thread.new do
            client_socket = tunnel[:server_socket].accept
            opts = {}
            if tunnel[:proxy_jump]
              opts[:proxy] = Net::SSH::Proxy::Jump.new(tunnel[:proxy_jump])
            end
            tunnel[:ssh] = Net::SSH.start(tunnel[:host], tunnel[:user], opts)
            tunnel[:forwarded_port] = tunnel[:ssh].forward.local(0, tunnel[:remote_host], tunnel[:remote_port])
            # add the connection to the pool
            upstream_socket = TCPSocket.new("localhost", tunnel[:forwarded_port])
            tunnel[:conns].push([client_socket, upstream_socket])
            # process SSH communication
            while run_ssh_thread do
              tunnel[:ssh].process(0.01)
              while !tunnel[:pending_conns].empty?
                client_socket = tunnel[:pending_conns].pop
                upstream_socket = TCPSocket.new("localhost", tunnel[:forwarded_port])
                tunnel[:conns].push([client_socket, upstream_socket])
              end
              Thread.pass
            end
          end
        end
      end
      tunnel[:conns].each do |conn|
        begin
          if sock == conn[0]
            conn[1].write(conn[0].read_nonblock(4096))
            printf ">"
          elsif sock == conn[1]
            conn[0].write(conn[1].read_nonblock(4096))
            printf "<"
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
