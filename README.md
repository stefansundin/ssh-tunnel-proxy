# ssh-tunnel-proxy

This is a fairly simple program that does the following:
- Opens TCP servers on startup.
- Upon receiving a connection, the program opens the SSH connection to the destination server, and forwards the connection.
  - The first connection takes a few seconds as the SSH connection is established.
  - Subsequent connections are fast as the SSH connection is still open.
  - After 5 minutes of inactivity with no open connections, the SSH connection is closed.
- Consumes negligible resources when idle.

See [ssh-tunnel-proxy.toml](ssh-tunnel-proxy.toml) for configuration examples.

# Install

### Mac

On Mac with Homebrew:

```bash
brew install stefansundin/tap/ssh-tunnel-proxy
BUNDLE_GEMFILE=$(brew --prefix)/opt/ssh-tunnel-proxy/libexec/Gemfile bundle install
```

Note: The service assumes that you are using rbenv, but you can easily change that.

### Debian/Ubuntu

```
sudo apt-get install apt-transport-https
curl -fsS https://stefansundin.github.io/deb/stefansundin.asc | sudo apt-key add -
echo "deb https://stefansundin.github.io/deb /" | sudo tee /etc/apt/sources.list.d/stefansundin.list
sudo apt-get update
sudo apt-get install -y ssh-tunnel-proxy
sudo systemctl enable ssh-tunnel-proxy
```

Please note that the systemd service will try to load the configuration from `/etc/ssh-tunnel-proxy.toml`, and you will not be able to use `~` in paths, and you have to manually specify the location of your ssh keys.

# Troubleshooting

If you have a lot of tunnels, then you will eventually need to increase the file descriptor limit:

```
# run before you start the program:
ulimit -n 4096
```
