# Pine DNS

This is a simple DNS server capable of handling A records and responding to queries.

Based on a CodeCrafters project

## Features

- Resolve queries using a given server and port
- Recursively resolve queries from the root name servers

## Planned Features

- Handling more record and query types

## Running the program

- Ensure you have `cargo (1.70)` installed locally
- The server runs on `127.0.0.1:2053`
- To use an existing resolver:
    - `./your_server.sh --resolver <ip:port>` where resolver is the ip and port of a functional dns resolver
- To recursively resolve:
    - `./your_server.sh`
- You can now use a tool such as `dig` to create dns queries and see them be resolved
    - ex `dig @127.0.0.1 -p 2053 www.google.com`
