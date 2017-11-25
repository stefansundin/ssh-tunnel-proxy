#!/usr/bin/env ruby
# frozen_string_literal: true
require "socket"
require "ipaddr"
require "net/ssh"
require "net/ssh/proxy/jump"
require "toml-rb"

Thread.abort_on_exception = true

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
        Thread.current[:conns].push(client)
        debug { "received connection on #{socket}" }

        channel = session.open_channel("direct-tcpip", :string, remote_host, :long, remote_port, :string, bind_address, local_port_type, local_port) do |achannel|
          achannel.info { "direct channel established" }
        end

        prepare_client(client, channel, :local)

        channel.on_open_failed do |ch, code, description|
          channel.error { "could not establish direct channel: #{description} (#{code})" }
          session.stop_listening_to(channel[:socket])
          channel[:socket].close
          Thread.current[:conns].delete(channel[:socket])
        end

        channel.on_close do |ch|
          Thread.current[:conns].delete(channel[:socket])
          Thread.current[:last_activity] = Time.now
        end
      end

      local_port
    end

    def dynamic2(socket)
      local_port_type = :long
      local_port = socket.addr[1]
      bind_address = socket.addr[2]
      @local_forwarded_ports[[local_port, bind_address]] = socket

      session.listen_to(socket) do |server|
        client = server.accept
        Thread.current[:conns].push(client)
        debug { "received connection on #{socket}" }

        version, = client.recv(1).unpack("C")
        if version == 4 # SOCKS4
          command, port = client.recv(4).unpack("Cn")
          raise "Unsupported SOCKS command: #{command}" if command != 1
          remote_host = IPAddr.ntop(client.recv(4))
          client.recv(16) # ignore user field
          client.send([0, 0x5A, 0, 0, 0, 0, 0, 0].pack("CCnN"), 0)
        elsif version == 5 # SOCKS5
          # https://tools.ietf.org/html/rfc1928
          auth_methods = client.recv(2).unpack("C2")
          raise "Unsupported auth method" if auth_methods != [1,0]
          client.send([5, 0].pack("C2"), 0)
          version, command, _, type = client.recv(4).unpack("C4")
          raise "Unsupported version or command: #{version} #{command}" if version != 5 || command != 1
          if type == 1 # IPv4
            remote_host = IPAddr.ntop(client.recv(4))
          elsif type == 3 # Domain name
            len, = client.recv(1).unpack("C")
            remote_host, = client.recv(len).unpack("a*")
          elsif type == 4 # IPv6
            remote_host = IPAddr.ntop(client.recv(16))
          else
            raise "Unsupported address type: #{type}"
          end
          port, = client.recv(2).unpack("n")
          client.send([5, 0, 0, 1, 0, 0, 0, 0, 0].pack("C4C4n"), 0) # Doesn't seem like you have to send back the same data, this is also how openssh does it
        else
          raise "Unsupported SOCKS version: #{version}"
        end

        channel = session.open_channel("direct-tcpip", :string, remote_host, :long, port, :string, bind_address, local_port_type, local_port) do |achannel|
          achannel.info { "direct channel established" }
        end

        prepare_client(client, channel, :local)

        channel.on_open_failed do |ch, code, description|
          channel.error { "could not establish direct channel: #{description} (#{code})" }
          session.stop_listening_to(channel[:socket])
          channel[:socket].close
          Thread.current[:conns].delete(channel[:socket])
        end

        channel.on_close do |ch|
          Thread.current[:conns].delete(channel[:socket])
          Thread.current[:last_activity] = Time.now
        end
      end

      local_port
    end
  end
end; end; end


config_path = File.exists?("ssh-tunnel-proxy.toml") ? "ssh-tunnel-proxy.toml" : File.expand_path("~/.ssh-tunnel-proxy.toml")
if File.exists?(config_path)
  puts "Loading config from: #{config_path}"
  config = TomlRB.load_file(config_path, symbolize_keys: true)
else
  puts "Could not find config file #{config_path}. Loading your SSH config."
  config = {import_all_hosts: true}
end

config[:tunnel] ||= []
config[:import_hosts] ||= []
tunnels = config[:tunnel]

if config[:import_all_hosts]
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
          local_interface: local_interface,
          local_port: local_port.to_i,
          remote_host: forward[1][0],
          remote_port: forward[1][1].to_i,
          user: host_config["user"],
          host: host_config["hostname"],
          proxy_jump: host_config["proxyjump"],
        })
      end
      host = value
      host_config = {}
    else
      host_config[key] = value
    end
  end
end

config[:import_hosts].each do |host|
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
    local_interface: local_interface,
    local_port: local_port.to_i,
    remote_host: forward[1][0],
    remote_port: forward[1][1].to_i,
    user: host_config["user"],
    host: host_config["hostname"],
    proxy_jump: host_config["proxyjump"],
  })
end

trap("INT") do
  puts "\nBye!"
  tunnels.each do |tunnel|
    if tunnel[:thread]
      tunnel[:thread][:active] = false
      tunnel[:thread].join
    end
    while !tunnel[:forward].empty?
      tunnel[:forward].pop[:server].close
    end
  end
  exit
end

if tunnels.empty?
  puts "There are no tunnels defined. Exiting."
  exit(1)
end

tunnels.each do |tunnel|
  tunnel[:forward].each do |forward|
    forward[:server] = TCPServer.new(forward[:local_interface], forward[:local_port])
    forward[:server].listen(128)
    if forward[:type] == "dynamic"
      puts "Forwarding #{forward[:local_interface]}:#{forward[:local_port]} (dynamic) via #{tunnel[:host]}#{tunnel[:proxy_jump] ? " (via proxy #{tunnel[:proxy_jump]})":""}"
    else
      puts "Forwarding #{forward[:local_interface]}:#{forward[:local_port]} to #{forward[:remote_host]}:#{forward[:remote_port]} via #{tunnel[:host]}#{tunnel[:proxy_jump] ? " (via proxy #{tunnel[:proxy_jump]})":""}"
    end
  end
end

loop do
  sockets = tunnels.select { |t| !t[:thread] }.map { |t| t[:forward].map { |f| f[:server] } }.flatten
  result = IO.select(sockets, nil, nil, 1)
  if result == nil
    a_while_ago = Time.now - 5*60
    tunnels.each do |tunnel|
      if tunnel[:thread] && tunnel[:thread][:conns].empty? && tunnel[:thread][:last_activity] < a_while_ago
        puts "Closing SSH connection to #{tunnel[:host]}#{tunnel[:proxy_jump] ? " (via proxy #{tunnel[:proxy_jump]})":""} because of inactivity..."
        tunnel[:thread][:active] = false
        tunnel[:thread].join
      end
    end
    next
  end
  result[0].each do |sock|
    tunnels.each do |tunnel|
      if tunnel[:forward].map { |f| f[:server] }.include?(sock)
        puts "Opening SSH connection to #{tunnel[:host]}#{tunnel[:proxy_jump] ? " (via proxy #{tunnel[:proxy_jump]})":""}..."
        tunnel[:thread] = Thread.new do
          begin
            Thread.current[:active] = false
            Thread.current[:conns] = []
            Thread.current[:last_activity] = Time.now
            opts = {}
            if tunnel[:opts]
              opts = tunnel[:opts]
            end
            if tunnel[:proxy_jump]
              opts[:proxy] = Net::SSH::Proxy::Jump.new(tunnel[:proxy_jump])
            end
            ssh = Net::SSH.start(tunnel[:host], tunnel[:user], opts)
            tunnel[:forward].each do |forward|
              if forward[:type] == "dynamic"
                ssh.forward.dynamic2(forward[:server])
              else
                ssh.forward.local2(forward[:server], forward[:remote_host], forward[:remote_port])
              end
            end
            # process SSH communication
            Thread.current[:active] = true
            while Thread.current[:active] do
              ssh.process(0.01)
              Thread.pass
            end
            ssh.close
          rescue => e
            puts "Exception in SSH thread: #{e}"
            if !Thread.current[:active]
              # The SSH tunnel failed to open, pick up the connection and close it
              sock.accept.close
            end
            while !Thread.current[:conns].empty?
              # Close any connections that are in flight
              Thread.current[:conns].pop.close
            end
          ensure
            tunnel[:thread] = nil
          end
        end
      end
    end
  end
end
