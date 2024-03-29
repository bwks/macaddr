# MacAddr

A Rust library for working with MAC Addresses.

### License 
[MIT](LICENSE)

### Usage
Update dependencies
### Cargo.toml
```toml
[dependencies]
macaddr = { git = "https://github.com/bwks/macaddr.git", branch = "main" }
```

#### Basic Usage
```rust
use macaddr::{MacAddress, MacAddressError};

fn main() -> Result<(), MacAddressError> {

    // Create a MAC address instance.
    let mac = MacAddress::parse("00:11:22:aa:bb:cc")?;

    // Access Methods
    println!("{}", mac.raw());

    Ok(())
}
```

### Methods
A `MacAddress` instance has the following methods.

```rust
mac.raw() // 001122aabbcc

mac.eui() // 00-11-22-aa-bb-cc

mac.hex() // 00:11:22:aa:bb:cc

mac.dot() // 0011.22aa.bbcc

mac.octets() // ["00", "11", "22", "aa", "bb", "cc"]

mac.bits() // ["0000", "0000", "0001", "0001", "0010", "0010", "1010", "1010", "1011", "1011", "1100", "1100"]

mac.binary() // 000000000001000100100010101010101011101111001100

mac.int() // 73596058572

mac.oui() // 001122

mac.nic() // aabbcc

mac.is_unicast() // true

mac.is_broadcast() // false

mac.is_multicast() // false

mac.is_local() // false

mac.is_universal() // true

mac.eui64() // 02-11-22-ff-fe-aa-bb-cc

mac.ipv6_link_local() // fe80::0211:22ff:feaa:bbcc
```