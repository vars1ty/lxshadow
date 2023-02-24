# lxshadow
Password-checking binding around /etc/shadow, without the direct use of unsafe code or libc calls.
## Usage example
```rust
fn main() {
    let result = is_eq("username", "password", true).expect("Failed reading /etc/shadow, check the log!").expect("Failed retrieving necessary info, check the log!");
    println!("is password eq: {result}")
}
```
