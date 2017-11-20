#!/usr/bin/env ruby
# frozen_string_literal: true
require "socket"
require "net/ssh"
require "net/ssh/proxy/jump"
require "toml-rb"

config_path = File.exists?("ssh-tunnel-proxy.toml") ? "ssh-tunnel-proxy.toml" : File.expand_path("~/.ssh-tunnel-proxy.toml")
puts "Loading config from: #{config_path}"

config = TomlRB.load_file(config_path)
tunnels = config["tunnel"]

trap("INT") do
  puts "\nBye!"
  tunnels.each do |tunnel|
    if tunnel["thread"]
      tunnel["thread"]["active"] = false
      tunnel["thread"].join
    end
    if tunnel["server_socket"] && !tunnel["server_socket"].closed?
      tunnel["server_socket"].close
    end
  end
  exit
end

tunnels.each do |tunnel|
  tunnel["server_socket"] = TCPServer.new(tunnel["local_interface"], tunnel["local_port"])
  tunnel["server_socket"].listen(128)
  tunnel["conns"] = []
  tunnel["pending_conns"] = []
  tunnel["last_activity"] = nil
end

puts "Started listening on ports: #{tunnels.map { |t| t["local_port"] }}"

loop do
  sockets = tunnels.map { |t| [t["server_socket"], t["conns"]] }.flatten
  result = IO.select(sockets, nil, nil, 1)
  if result == nil
    a_while_ago = Time.now - 5*60
    tunnels.each do |tunnel|
      if tunnel["ssh"] && tunnel["conns"].empty? && tunnel["pending_conns"].empty? && tunnel["last_activity"] && tunnel["last_activity"] < a_while_ago
        puts "Closing SSH connection to #{tunnel["host"]}:#{tunnel["remote_port"]}#{tunnel["proxy_jump"] ? " (via #{tunnel["proxy_jump"]})":""} because of inactivity..."
        tunnel["thread"]["active"] = false
        tunnel["thread"].join
        tunnel["conns"] = []
        tunnel["pending_conns"] = []
        tunnel["last_activity"] = nil
      end
    end
    next
  end
  result[0].each do |sock|
    tunnels.each do |tunnel|
      if sock == tunnel["server_socket"]
        printf "/"
        tunnel["pending_conns"].push(tunnel["server_socket"].accept)
        if !tunnel["ssh"]
          tunnel["ssh"] = true
          puts
          puts "Opening SSH connection to #{tunnel["host"]}:#{tunnel["remote_port"]}#{tunnel["proxy_jump"] ? " (via #{tunnel["proxy_jump"]})":""}..."
          tunnel["thread"] = Thread.new do
            Thread.current["active"] = true
            opts = {}
            if tunnel["proxy_jump"]
              opts[:proxy] = Net::SSH::Proxy::Jump.new(tunnel["proxy_jump"])
            end
            tunnel["ssh"] = Net::SSH.start(tunnel["host"], tunnel["user"], opts)
            tunnel["forwarded_port"] = tunnel["ssh"].forward.local(tunnel["forwarded_port"] || 0, tunnel["remote_host"], tunnel["remote_port"])
            # process SSH communication
            while Thread.current["active"] do
              while !tunnel["pending_conns"].empty?
                client_socket = tunnel["pending_conns"].pop
                upstream_socket = TCPSocket.new("localhost", tunnel["forwarded_port"])
                tunnel["conns"].push([client_socket, upstream_socket])
              end
              tunnel["ssh"].process(0.01)
              Thread.pass
            end
            tunnel["ssh"].forward.cancel_local(tunnel["forwarded_port"])
            tunnel["ssh"].close
            tunnel["ssh"] = nil
          end
        end
      end
      tunnel["conns"].each do |conn|
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
          tunnel["conns"].delete(conn)
          tunnel["last_activity"] = Time.now
          puts "!"
          break
        end
      end
    end
  end
end
