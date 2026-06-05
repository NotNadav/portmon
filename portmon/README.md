# PortMon

A small GUI that lists every TCP/UDP socket on your machine and the process that
owns it. Think Windows TCPView or `netstat`, but easier to read. Written in Rust
with [egui](https://github.com/emilk/egui).

## Features

- Live table of every TCP and UDP socket, refreshed automatically.
- PID and process name for each socket.
- Well-known ports shown by name (443 = https, 22 = ssh, 3306 = mysql).
- Remote IPs resolved to hostnames in the background, raw IP on hover.
- Right-click a row to end the process or copy an address.
- Search, filter (TCP / UDP / listening only), and sort any column.

UDP sockets on port 443 or 80 are tagged `UDP·QUIC?`. QUIC runs over UDP and
there's no reliable way to spot it at the socket level, so that label is a guess.
The plain TCP and UDP labels are accurate.

## Build and run

You need the [Rust toolchain](https://rustup.rs/), then:

```sh
cargo run --release
```

The executable lands at `target/release/portmon.exe`. Copy it anywhere and run it.

## Windows notes

It was built with the GNU toolchain, so no Visual Studio Build Tools are needed:

```sh
rustup toolchain install stable-x86_64-pc-windows-gnu
rustup default stable-x86_64-pc-windows-gnu
```

The default MSVC toolchain works too if you have the C++ Build Tools installed.

If `cargo` can't reach crates.io behind a strict proxy, `.cargo/config.toml`
turns off the cert-revocation check. Delete that file if you don't need it.

## License

[MIT](LICENSE).
