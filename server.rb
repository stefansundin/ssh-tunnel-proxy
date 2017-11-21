#!/usr/bin/env ruby
# frozen_string_literal: true
require "socket"
require "net/ssh"
require "net/ssh/proxy/jump"
require "toml-rb"

config_path = File.exists?("ssh-tunnel-proxy.toml") ? "ssh-tunnel-proxy.toml" : File.expand_path("~/.ssh-tunnel-proxy.toml")
if File.exists?(config_path)
  puts "Loading config from: #{config_path}"
  config = TomlRB.load_file(config_path)
else
  puts "Could not find config file #{config_path}. Loading your SSH config."
  config = {"import_all_hosts" => true}
end

config["tunnel"] ||= []
config["import_hosts"] ||= []
tunnels = config["tunnel"]

if config["import_all_hosts"]
  # This is a bit ugly, not sure I want to keep it
  # I wish net-ssh would help with this
  host = nil
  host_config = {}
  File.read(File.expand_path("~/.ssh/config")).split("\n").each do |line|
    next if line =~ /^\s*(?:#.*)?$/
    key, value = line.strip.split(/\s+/, 2)
    next if value.nil?
    key.downcase!
    if key == "host"
      if host && host_config["localforward"]
        forward = host_config["localforward"].split(" ").map { |s| s.split(":") }
        local_interface = forward[0].length == 2 ? forward[0][0] : "localhost"
        local_interface = nil if local_interface == "*"
        local_port = forward[0].length == 1 ? forward[0][0] : forward[0][1]
        tunnels.push({
          "local_interface" => local_interface,
          "local_port" => local_port.to_i,
          "remote_host" => forward[1][0],
          "remote_port" => forward[1][1].to_i,
          "user" => host_config["user"],
          "host" => host_config["hostname"],
          "proxy_jump" => host_config["proxyjump"],
        })
      end
      host = value
      host_config = {}
    else
      host_config[key] = value
    end
  end
end

config["import_hosts"].each do |host|
  host_config = Net::SSH::Config.load("~/.ssh/config", host)
  if !host_config["localforward"]
    puts "Skipping #{host} because of missing LocalForward setting."
    next
  end
  forward = host_config["localforward"].split(" ").map { |s| s.split(":") }
  local_interface = forward[0].length == 2 ? forward[0][0] : "localhost"
  local_interface = nil if local_interface == "*"
  local_port = forward[0].length == 1 ? forward[0][0] : forward[0][1]
  tunnels.push({
    "local_interface" => local_interface,
    "local_port" => local_port.to_i,
    "remote_host" => forward[1][0],
    "remote_port" => forward[1][1].to_i,
    "user" => host_config["user"],
    "host" => host_config["hostname"],
    "proxy_jump" => host_config["proxyjump"],
  })
end

trap("INT") do
  puts "\nBye!"
  tunnels.each do |tunnel|
    if tunnel["thread"]
      tunnel["thread"]["active"] = false
      tunnel["thread"].join
    end
    if !tunnel["server_socket"].closed?
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
  puts "Waiting for connection on #{tunnel["local_interface"]}:#{tunnel["local_port"]} for #{tunnel["remote_host"]}:#{tunnel["remote_port"]} on #{tunnel["host"]} #{tunnel["proxy_jump"] ? " (via #{tunnel["proxy_jump"]})":""}"
end

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
        if tunnel["ssh"]
          if tunnel["forwarded_port"]
            client_socket = tunnel["server_socket"].accept
            upstream_socket = TCPSocket.new("localhost", tunnel["forwarded_port"])
            tunnel["conns"].push([client_socket, upstream_socket])
          else
            tunnel["pending_conns"].push(tunnel["server_socket"].accept)
          end
        else
          tunnel["pending_conns"].push(tunnel["server_socket"].accept)
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
            while !tunnel["pending_conns"].empty?
              client_socket = tunnel["pending_conns"].pop
              upstream_socket = TCPSocket.new("localhost", tunnel["forwarded_port"])
              tunnel["conns"].push([client_socket, upstream_socket])
            end
            # process SSH communication
            while Thread.current["active"] do
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
