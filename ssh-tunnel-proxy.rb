#!/usr/bin/env ruby
# frozen_string_literal: true
require "socket"
require "ipaddr"
require "fileutils"
require "net/ssh"
require "net/ssh/proxy/jump"
require "toml-rb"

STDOUT.sync = true
STDERR.sync = true

Thread.abort_on_exception = true

# https://github.com/rails/rails/blob/master/activesupport/lib/active_support/core_ext/hash/except.rb
class Hash
  def except(*keys)
    slice(*self.keys - keys)
  end
end

# Monkeypatch a new method into net-ssh that receives a socket
module Net; module SSH; module Service
  class Forward
    def local2(*args)
      if args.length < 2 || args.length > 4
        raise ArgumentError, "expected 2 to 4 parameters, got #{args.length}"
      end

      if defined?(UNIXServer) and args.first.class == UNIXServer
        socket = args.shift
        bind_address = nil
        local_port_type = :string
        local_port = nil

        local_socket_path = socket.addr[1]
        @local_forwarded_sockets[local_socket_path] = socket
      elsif args.first.class == TCPServer
        socket = args.shift
        bind_address = socket.addr[2]
        local_port_type = :long
        local_port = socket.addr[1]

        @local_forwarded_ports[[local_port, bind_address]] = socket
      else
        bind_address = "127.0.0.1"
        bind_address = args.shift if args.first.is_a?(String) && args.first =~ /\D/
        local_port_type = :long
        local_port = args.shift.to_i
        socket = TCPServer.new(bind_address, local_port)

        local_port = socket.addr[1] if local_port == 0 # ephemeral port was requested
        @local_forwarded_ports[[local_port, bind_address]] = socket
      end

      if args.length == 2
        remote_host = args.shift
        remote_port = args.shift.to_i
        channel_args = ["direct-tcpip", :string, remote_host, :long, remote_port, :string, bind_address, local_port_type, local_port]
      else
        remote_socket_path = args.shift
        channel_args = ["direct-streamlocal@openssh.com", :string, remote_socket_path, :string, nil, :long, 0]
      end

      session.listen_to(socket) do |server|
        client = server.accept
        Thread.current[:conns].push(client)
        debug { "received connection on #{socket}" }

        channel = session.open_channel(*channel_args) do |achannel|
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
ssh_config_path = File.expand_path("~/.ssh/config")

if File.exists?(config_path)
  puts "Loading config from: #{config_path}"
  config = TomlRB.load_file(config_path, symbolize_keys: true)
else
  puts "Could not find config file #{config_path}. Loading your SSH config."
  config = { import_all_hosts: File.exists?(ssh_config_path) }
end

config[:tunnel] ||= []
config[:import_hosts] ||= []
config[:timeout] ||= nil
tunnels = config[:tunnel].select { |t| t[:forward] != nil }

if config[:import_all_hosts]
  # This is a bit ugly, not sure I want to keep it
  # I wish net-ssh would help with this
  array_keys = %w[localforward dynamicforward identityfile]
  host = nil
  host_config = {}
  File.read(ssh_config_path).split("\n").push(nil).each do |line|
    if line != nil
      next if line =~ /^\s*(?:#.*)?$/
      key, value = line.strip.split(/\s+/, 2)
      next if value.nil?
      key.downcase!
    end
    if key == "host" || line == nil
      if host && (host_config["localforward"] || host_config["dynamicforward"])
        tunnel = {
          user: host_config["user"],
          host: host_config["hostname"],
          proxy_jump: host_config["proxyjump"],
          opts: {},
          forward: [],
        }
        tunnel[:opts][:port] = host_config["port"] if host_config["port"]
        tunnel[:opts][:keys] = host_config["identityfile"] if host_config["identityfile"]
        host_config["localforward"].each do |forward|
          forward = forward.split(" ").map { |s| s.split(":") }
          local_interface = forward[0].length == 2 ? forward[0][0] : "localhost"
          local_interface = nil if local_interface == "*"
          local_port = forward[0].length == 1 ? forward[0][0] : forward[0][1]
          tunnel[:forward].push({
            type: "local",
            local_interface: local_interface,
            local_port: local_port.to_i,
            remote_host: forward[1][0],
            remote_port: forward[1][1].to_i,
          })
        end if host_config["localforward"]
        host_config["dynamicforward"].each do |forward|
          forward = forward.split(" ").map { |s| s.split(":") }
          local_interface = forward[0].length == 2 ? forward[0][0] : "localhost"
          local_interface = nil if local_interface == "*"
          local_port = forward[0].length == 1 ? forward[0][0] : forward[0][1]
          tunnel[:forward].push({
            type: "dynamic",
            local_interface: local_interface,
            local_port: local_port.to_i,
          })
        end if host_config["dynamicforward"]
        tunnels.push(tunnel)
      end
      host = value
      host_config = {}
    else
      if array_keys.include?(key)
        host_config[key] ||= []
        host_config[key].push(value)
      else
        host_config[key] = value
      end
    end
  end
end

config[:import_hosts].each do |host|
  host_config = Net::SSH::Config.load("~/.ssh/config", host)
  if !host_config["localforward"] && !host_config["dynamicforward"]
    puts "Skipping #{host} because of missing LocalForward and DynamicForward setting."
    next
  end
  tunnel = {
    user: host_config["user"],
    host: host_config["hostname"],
    proxy_jump: host_config["proxyjump"],
    opts: {},
    forward: [],
  }
  tunnel[:opts][:port] = host_config["port"] if host_config["port"]
  tunnel[:opts][:keys] = host_config["identityfile"] if host_config["identityfile"]
  if host_config["localforward"]
    forward = host_config["localforward"].split(" ").map { |s| s.split(":") }
    local_interface = forward[0].length == 2 ? forward[0][0] : "localhost"
    local_interface = nil if local_interface == "*"
    local_port = forward[0].length == 1 ? forward[0][0] : forward[0][1]
    tunnel[:forward].push({
      type: "local",
      local_interface: local_interface,
      local_port: local_port.to_i,
      remote_host: forward[1][0],
      remote_port: forward[1][1].to_i,
    })
  end
  if host_config["dynamicforward"]
    forward = host_config["dynamicforward"].to_s.split(" ").map { |s| s.split(":") }
    local_interface = forward[0].length == 2 ? forward[0][0] : "localhost"
    local_interface = nil if local_interface == "*"
    local_port = forward[0].length == 1 ? forward[0][0] : forward[0][1]
    tunnel[:forward].push({
      type: "dynamic",
      local_interface: local_interface,
      local_port: local_port.to_i,
    })
  end
  tunnels.push(tunnel)
end

tunnels.each do |tunnel|
  tunnel[:opts][:verbose] = tunnel[:opts][:verbose].to_sym if tunnel[:opts] && tunnel[:opts][:verbose]
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

if tunnels.empty? && !config[:control_socket]
  puts "There are no tunnels defined. Exiting."
  exit(1)
end

if config[:control_socket]
  fn = File.expand_path(config[:control_socket])
  if File.exist?(fn)
    abort "Error: Refusing to clean up existing file #{fn} since it is not a socket file. Please move or delete it manually." if !File.socket?(fn)
    File.delete(fn)
  end
  dir = File.dirname(File.expand_path(fn))
  if !File.directory?(dir)
    FileUtils.mkdir_p(dir)
  end
  puts "Control socket: #{fn}"
  config[:control_socket] = UNIXServer.new(fn)
end

tunnels.each do |tunnel|
  tunnel[:forward].each do |forward|
    if forward[:local_socket]
      fn = File.expand_path(forward[:local_socket])
      if File.exist?(fn)
        abort "Error: Refusing to clean up existing file #{fn} since it is not a socket file. Please move or delete it manually." if !File.socket?(fn)
        File.delete(fn)
      end
      dir = File.dirname(File.expand_path(fn))
      if !File.directory?(dir)
        FileUtils.mkdir_p(dir)
      end
      forward[:server] = UNIXServer.new(fn)
    else
      forward[:server] = TCPServer.new(forward[:local_interface], forward[:local_port])
    end
    forward[:server].listen(128)
    if forward[:type] == "dynamic"
      puts "Forwarding #{forward[:local_interface]}:#{forward[:local_port]} (dynamic) via #{tunnel[:host]}#{tunnel[:proxy_jump] ? " (via proxy #{tunnel[:proxy_jump]})":""}"
    else
      puts "Forwarding #{forward[:local_socket] || "#{forward[:local_interface]}:#{forward[:local_port]}"} to #{forward[:remote_socket] || "#{forward[:remote_host]}:#{forward[:remote_port]}"} via #{tunnel[:host]}#{tunnel[:proxy_jump] ? " (via proxy #{tunnel[:proxy_jump]})":""}"
    end
  end
end

loop do
  sockets = tunnels.select { |t| !t[:thread] }.map { |t| t[:forward].map { |f| f[:server] } }.flatten
  sockets.push(config[:control_socket]) if config[:control_socket]
  result = IO.select(sockets, nil, nil, 1)
  if result == nil && config[:timeout]
    a_while_ago = Time.now - config[:timeout]
    tunnels.each do |tunnel|
      if tunnel[:thread] && tunnel[:thread][:conns].empty? && tunnel[:thread][:last_activity] < a_while_ago
        puts "Closing SSH connection to #{tunnel[:host]}#{tunnel[:proxy_jump] ? " (via proxy #{tunnel[:proxy_jump]})":""} because of inactivity..."
        tunnel[:thread][:active] = false
        tunnel[:thread].join
      end
    end
  end
  next if result == nil
  result[0].each do |sock|
    # Control socket
    if sock == config[:control_socket]
      puts "Connection on control socket."
      client = sock.accept
      data = client.read
      client.close

      if data == "print_config"
        puts tunnels.inspect
        next
      end
      puts "New configuration:"
      puts data

      new_config = TomlRB.parse(data, symbolize_keys: true)
      new_config[:tunnel].each do |new_tunnel|
        tunnel_config = new_tunnel.except(:forward)
        existing_tunnel = tunnels.find { |t| t.except(:forward, :thread) == tunnel_config }
        if existing_tunnel
          puts "Adding to existing tunnel."
          tunnel = existing_tunnel
          new_tunnel[:forward].reject! do |forward|
            if tunnel[:forward].any? { |f| f.except(:server) == forward }
              puts "Tunnel already configured. Ignoring: #{forward.inspect}"
              next true
            end
            next false
          end
          if new_tunnel[:forward].empty?
            puts "No tunnels left."
            next
          end
        else
          tunnel = tunnel_config
          tunnel[:forward] = []
        end

        new_tunnel[:forward].each do |forward|
          if forward[:local_socket]
            fn = File.expand_path(forward[:local_socket])
            if File.exist?(fn)
              abort "Error: Refusing to clean up existing file #{fn} since it is not a socket file. Please move or delete it manually." if !File.socket?(fn)
              File.delete(fn)
            end
            dir = File.dirname(File.expand_path(fn))
            if !File.directory?(dir)
              FileUtils.mkdir_p(dir)
            end
            forward[:server] = UNIXServer.new(fn)
          else
            forward[:server] = TCPServer.new(forward[:local_interface], forward[:local_port])
          end
          forward[:server].listen(128)
          if forward[:type] == "dynamic"
            puts "Forwarding #{forward[:local_interface]}:#{forward[:local_port]} (dynamic) via #{tunnel[:host]}#{tunnel[:proxy_jump] ? " (via proxy #{tunnel[:proxy_jump]})":""}"
          else
            puts "Forwarding #{forward[:local_socket] || "#{forward[:local_interface]}:#{forward[:local_port]}"} to #{forward[:remote_socket] || "#{forward[:remote_host]}:#{forward[:remote_port]}"} via #{tunnel[:host]}#{tunnel[:proxy_jump] ? " (via proxy #{tunnel[:proxy_jump]})":""}"
          end
        end

        tunnel[:forward].push(*new_tunnel[:forward])
        if tunnel[:thread]
          tunnel[:thread][:new_forwards] = new_tunnel[:forward]
        end

        if !existing_tunnel
          tunnels.push(tunnel)
        end
      end
      next
    end

    # Tunnels
    tunnels.each do |tunnel|
      if tunnel[:forward].map { |f| f[:server] }.include?(sock)
        puts "Opening SSH connection to #{tunnel[:host]}#{tunnel[:proxy_jump] ? " (via proxy #{tunnel[:proxy_jump]})":""}..."
        tunnel[:thread] = Thread.new do
          begin
            Thread.current[:active] = false
            Thread.current[:new_forwards] = tunnel[:forward]
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
            # process SSH communication
            Thread.current[:active] = true
            while Thread.current[:active] do
              if !Thread.current[:new_forwards].empty?
                Thread.current[:new_forwards].each do |forward|
                  if forward[:type] == "dynamic"
                    ssh.forward.dynamic2(forward[:server])
                  elsif forward[:remote_socket]
                    ssh.forward.local2(forward[:server], forward[:remote_socket])
                  else
                    ssh.forward.local2(forward[:server], forward[:remote_host], forward[:remote_port])
                  end
                end
                Thread.current[:new_forwards] = []
              end
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
