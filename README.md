# hedproxy

Routes `.onion` domains over tor, `.i2p` domains over i2p, and `.loki` domains over lokinet through their respective SOCKS proxies. 

*hedproxy is a fork of [fedproxy](https://github.com/majestrate/fedproxy) by [majestrate](https://github.com/majestrate).* 

## Install 
```bash 
go install github.com/sandwichfarm/hedproxy
```

## Building

```bash
$ go get -u github.com/sandwichfarm/hedproxy
$ cp $(GOPATH)/bin/hedproxy /usr/local/bin/hedproxy
```

## Usage

Basic usage:
```bash
$ hedproxy -proto <protocol> -bind <address> [proxy flags] [other flags]
```

### Required Flags
- `-proto`: Protocol to use ("http" or "socks")
- `-bind`: Address to bind to (e.g., "127.0.0.1:2000")

### Proxy Flags (at least one required)
- `-tor`: Tor SOCKS proxy address (e.g., "127.0.0.1:9050")
- `-i2p`: I2P SOCKS proxy address (e.g., "127.0.0.1:4447")
- `-loki`: Lokinet SOCKS proxy address (e.g., "127.0.0.1:9050")

### Optional Flags
- `-verbose`: Enable verbose logging (default: false)
- `-passthrough`: Set passthrough mode (e.g., 'clearnet' for direct clearnet access)

### Examples

1. Basic SOCKS proxy with Tor only:
```bash
$ hedproxy -proto socks -bind 127.0.0.1:2000 -tor 127.0.0.1:9050
```

2. HTTP proxy with all networks and verbose logging:
```bash
$ fhedproxyedproxy -proto http -bind 127.0.0.1:8080 -tor 127.0.0.1:9050 -i2p 127.0.0.1:4447 -loki 127.0.0.1:9050 -verbose
```

3. SOCKS proxy with I2P and clearnet passthrough:
```bash
$ hedproxy -proto socks -bind 127.0.0.1:2000 -i2p 127.0.0.1:4447 -passthrough clearnet
```

4. HTTP proxy with Tor and Lokinet:
```bash
$ hedproxy -proto http -bind 127.0.0.1:8080 -tor 127.0.0.1:9050 -loki 127.0.0.1:9050
```

The proxy will be available at the specified bind address. Each network (.onion, .i2p, .loki) will only be accessible if its respective proxy is configured. Requests to unconfigured networks will return an error.

## Why the fork?
I liked **fedproxy** but needed a less opinionated solution.

**fedproxy** is loki-first, assumes loki is running over VPN/transparent proxy (default Loki desktop experience) and treats tor and i2p as second-class citizens, and clearnet as a third-class citizen.
**hedproxy** treats all as first class citizens and assumes nothing.

## Differences from fedproxy

- Logging is off by default (use `-v` to enable loggingg)
- Uses flags instead of positional arguments
- lokinet has same routing pattern as tor and i2p instead of assuming the host will handle it with a transparent proxy.
- A flag for clearnet URLS to be optionally routed through clearnet instead of tor.
- Fixed a few lingering bugs

## Acknowledgements

**hedproxy** is a fork of the spectacular [fedproxy](https://github.com/majestrate/fedproxy) by [majestrate](https://github.com/majestrate). 
