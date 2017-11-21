#!/usr/bin/env ruby
# frozen_string_literal: true
require "socket"
require "net/ssh"
require "net/ssh/proxy/jump"
require "toml-rb"

# Monkeypatch a new method into net-ssh that receives a socket
module Net; module SSH; module Service
  class Forward
    def local2(*args)
      if args.length < 3 || args.length > 4
        raise ArgumentError, "expected 3 or 4 parameters, got #{args.length}"
      end

      local_port_type = :long

      socket = args.shift
      local_port = socket.addr[1]
      bind_address = socket.addr[2]
      remote_host = args.shift
      remote_port = args.shift.to_i

      @local_forwarded_ports[[local_port, bind_address]] = socket

      session.listen_to(socket) do |server|
        client = server.accept
        debug { "received connection on #{socket}" }

        channel = session.open_channel("direct-tcpip", :string, remote_host, :long, remote_port, :string, bind_address, local_port_type, local_port) do |achannel|
          achannel.info { "direct channel established" }
        end

        prepare_client(client, channel, :local)

        channel.on_open_failed do |ch, code, description|
          channel.error { "could not establish direct channel: #{description} (#{code})" }
          session.stop_listening_to(channel[:socket])
          channel[:socket].close
        end
      end

      local_port
    end
  end
end; end; end


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
  puts "Waiting for connection on #{tunnel["local_interface"]}:#{tunnel["local_port"]} for #{tunnel["remote_host"]}:#{tunnel["remote_port"]} on #{tunnel["host"]} #{tunnel["proxy_jump"] ? " (via #{tunnel["proxy_jump"]})":""}"
end

loop do
  sockets = tunnels.select { |t| !t["ssh"] }.map { |t| t["server_socket"] }
  result = IO.select(sockets, nil, nil, 1)
  if result == nil
    next
  end
  result[0].each do |sock|
    tunnels.each do |tunnel|
      if sock == tunnel["server_socket"]
        tunnel["ssh"] = true
        puts "Opening SSH connection to #{tunnel["host"]}:#{tunnel["remote_port"]}#{tunnel["proxy_jump"] ? " (via #{tunnel["proxy_jump"]})":""}..."
        tunnel["thread"] = Thread.new do
          Thread.current["active"] = true
          opts = {}
          if tunnel["proxy_jump"]
            opts[:proxy] = Net::SSH::Proxy::Jump.new(tunnel["proxy_jump"])
          end
          tunnel["ssh"] = Net::SSH.start(tunnel["host"], tunnel["user"], opts)
          tunnel["ssh"].forward.local2(tunnel["server_socket"], tunnel["remote_host"], tunnel["remote_port"])
          # process SSH communication
          while Thread.current["active"] do
            tunnel["ssh"].process(0.01)
            Thread.pass
          end
          tunnel["ssh"].close
          tunnel["ssh"] = nil
        end
      end
    end
  end
end
