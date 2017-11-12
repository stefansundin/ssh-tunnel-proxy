#!/usr/bin/env ruby
require "socket"

listen_port = 9090
upstream_port = 8881

open_conns = []
server_socket = TCPServer.new(listen_port)
server_socket.listen(128)
loop do
  read_sockets = [server_socket, open_conns].flatten
  result = IO.select(read_sockets)
  result[0].each do |sock|
    if sock == server_socket
      client_socket = server_socket.accept
      puts "/"
      upstream_socket = TCPSocket.new("localhost", upstream_port)
      open_conns.push([client_socket, upstream_socket])
    else
      open_conns.each do |conn|
        begin
          if sock == conn[0]
            printf "."
            conn[1].write(conn[0].read_nonblock(4096))
          elsif sock == conn[1]
            printf "."
            conn[0].write(conn[1].read_nonblock(4096))
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
