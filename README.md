# sockops-rs-example

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo build --release
```
```
$:~/ebpf-sockops-rs/target/bpfel-unknown-none/release$ ls
skmsg-rs    sockops-rs 
```

## test
```
# start a TCP listener at port 1000, and echo back the received data
$ sudo socat TCP4-LISTEN:1000,fork exec:cat

```
```
# connect to the local TCP listener at port 1000
$ nc localhost 1000
```

## trace
```
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## ref
https://arthurchiao.art/blog/socket-acceleration-with-ebpf-zh/