# HTTP 1.1 Server

This is an HTTP 1.1 server implementation in C, currently WIP. The main challenges in implementing this server were supporting persistant connections and (to-be-completed) chunked Transfer-Encoding. If time permits I might make this even harder with multi-threading.

This implementation builds on Berkeley Sockets and is Unix-compatible, and aims to be fully cross-platform.

## External libraries

### Libevent

Libevent provides much of the functionality needed to implement an efficient event loop and general socket functionality cross-platform.

### picohttpparser

Used the picohttpparser library to parse incoming HTTP messages.

### GNU gperf

Used GNU gperf to generate compile-time perfect hash tables for the HTTP headers.
