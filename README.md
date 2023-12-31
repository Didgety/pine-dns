# Pine DNS

This is a simple DNS server capable of handling A, NS, CNAME, MX, and AAAA records and responding to queries.

Based on a CodeCrafters project

## Features

- Resolve queries using a given server and port
- Recursively resolve queries from the root name servers

## Planned Features

- Handling more record and query types
- Concurrency
- TCP support
- Host your own zones
- Authoritative nameserver functionality
- DNSSEC support to protect against DNS poisoning attacks

## Running the program

- Ensure you have `cargo (1.70)` installed locally
- The server runs on `127.0.0.1:2053`
- To use an existing resolver:
    - `./your_server.sh --resolver <ip:port>` where resolver is the ip and port of a functional dns resolver such as Google's `8.8.8.8:53`
- To recursively resolve:
    - `./your_server.sh`
- On windows replace `./your_server.sh` with `cargo run --quiet --release --target-dir=/tmp/pine-dns-target 
--manifest-path $(dirname $0) Cargo.toml -- "$@"`
- You can now use a tool such as `dig` to create dns queries and see them be resolved
    - ex `dig @127.0.0.1 -p 2053 www.google.com`
