# dr-fate
A web server port written in Rust!

Requirements:
1. Rustup
2. For MSVC: Microsoft Visual C++ and Windows 10/11 SDK
3. A lot of determination

To run the project with hot-reloading:

```
systemfd --no-pid -s http::6942 -- cargo watch -x run
```

Otherwise, simply do:

```
cargo run
```