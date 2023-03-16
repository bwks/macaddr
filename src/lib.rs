#[derive(Debug, PartialEq)]
pub enum MacAddressError {
    InvalidLength(String),
    InvalidMac(String),
}

impl std::fmt::Display for MacAddressError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MacAddressError::InvalidLength(a) => {
                write!(f, "address: `{a}` is not 12 characters long")
            }
            MacAddressError::InvalidMac(a) => write!(f, "address: `{a}` is not a MAC adddress"),
        }
    }
}

#[derive(Debug)]
pub struct MacAddress {
    eui48: Vec<u8>,
    eui64: Vec<u8>,
}

impl MacAddress {
    /// Parse a &str to a MAC address. MAC addresses can be in
    /// any format with common or no delimiters ie:
    ///  - 00:11:22:aa:bb:cc
    ///  - 00-11-22-aa-bb-cc
    ///  - 0011.22aa.bbcc
    ///  - 001122aabbcc
    ///  - 00 11 22 AA BB CC
    ///  - 001122-AABBCC
    pub fn parse(address: &str) -> Result<Self, MacAddressError> {
        // get raw address by removing known MAC delimiters,
        // trimming any whitespace and transforming to lowercase
        let raw = address
            .trim()
            .replace([':', '-', '.', ' '], "")
            .to_lowercase();

        // Valid MAC addresses have 12 chars, confirm the length == 12
        if raw.chars().count() != 12 {
            return Err(MacAddressError::InvalidLength(address.to_owned()));
        }

        let mut eui48: Vec<u8> = Vec::new();
        for c in raw.chars() {
            match c {
                // confirm address is made up of valid HEX chars
                '0'..='9' | 'a'..='f' => eui48.push(match c.to_digit(16) {
                    Some(i) => i as u8,
                    None => return Err(MacAddressError::InvalidMac(address.to_owned())),
                }),
                _ => return Err(MacAddressError::InvalidMac(address.to_owned())),
            };
        }

        let eui64 = eui48_to_eui64(&eui48);

        Ok(Self { eui48, eui64 })
    }

    /// Returns the MAC address in the format `001122aabbcc`
    pub fn raw(&self) -> String {
        format_mac(&self.eui48, "", 0)
    }

    /// Returns the MAC address in the format `00-11-22-aa-bb-cc`
    pub fn eui(&self) -> String {
        format_mac(&self.eui48, "-", 2)
    }

    /// Returns the MAC address in the format `00:11:22:aa:bb:cc`
    pub fn hex(&self) -> String {
        format_mac(&self.eui48, ":", 2)
    }

    /// Returns the MAC address in the format `0011.22aa.bbcc`
    pub fn dot(&self) -> String {
        format_mac(&self.eui48, ".", 4)
    }

    /// Returns the octets representation of the MAC address  
    /// in the format `["00", "11", "22", "aa", "bb", "cc"]`
    pub fn octets(&self) -> Vec<String> {
        self.eui48
            .chunks_exact(2)
            .map(|i| format!("{:x}{:x}", i[0], i[1]))
            .collect()
    }

    /// Returns the bits representation of the MAC address in the
    /// format `[0000", "0000", "0001", "0001", "0010", "0010", "1010", "1010", "1011", "1011", "1100", "1100"]`
    pub fn bits(&self) -> Vec<String> {
        self.eui48.iter().map(|i| format!("{:04b}", i)).collect()
    }

    /// Returns the binary representation of the MAC address in the
    /// format `000000000001000100100010101010101011101111001100`
    pub fn binary(&self) -> String {
        self.bits().join("")
    }

    /// Returns the Organizationally Unique Identifier (OUI) portion of the
    /// MAC address in the format `001122`
    pub fn oui(&self) -> String {
        self.eui48[0..=5]
            .iter()
            .map(|i| format!("{:x}", i))
            .collect()
    }

    /// Returns the Network Interface Card (NIC) portion of the
    /// MAC address in the format `aabbcc`
    pub fn nic(&self) -> String {
        self.eui48[6..=11]
            .iter()
            .map(|i| format!("{:x}", i))
            .collect()
    }

    /// Broadcast MAC addresses are all `ffffffffffff`
    /// Returns true if MAC address is in the format `ffffffffffff`
    pub fn is_broadcast(&self) -> bool {
        self.eui48 == vec![15; 12]
    }

    /// Multicast MAC addresses start with 01005e
    /// Returns true if the MAC address starts with `01005e`
    pub fn is_multicast(&self) -> bool {
        self.eui48[0..=5] == vec![0, 1, 0, 0, 5, 14]
    }

    /// Returns true if the MAC address is a unicast address
    pub fn is_unicast(&self) -> bool {
        !(self.is_broadcast() || self.is_multicast())
    }

    /// Universal (U) or Global MAC addresses have their 7th bit set to 0.
    pub fn is_universal(&self) -> bool {
        (self.eui48[1] >> 1) & 1 == 0
    }

    /// Local (L) MAC addresses have their 7th bit set to 1.
    pub fn is_local(&self) -> bool {
        (self.eui48[1] >> 1) & 1 == 1
    }

    /// Returns an EUI-64 address from the EUI-48 address in
    /// the format `00-11-22-ff-fe-aa-bb-cc`
    pub fn eui64(&self) -> String {
        format_mac(&self.eui64, "-", 2)
    }

    /// Returns an IPv6 Link Local address from the EUI-48 address in
    /// the format `fe80::0011:22ff:feaa:bbcc`
    pub fn ipv6_link_local(&self) -> String {
        format!("fe80::{}", format_mac(&self.eui64, ":", 4))
    }
}

impl std::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "EUI-48: {}\nEUI-64: {}", self.eui(), self.eui64())
    }
}

// Converts an EUI-48 address to an EUI-46 address.
// A converted EUI-64 address has the  Universal/Local (U/L)
// bit inverted. The U/L bit is the 7th but in the first octet.
// Reference RFC: http://www.faqs.org/rfcs/rfc2373.html
//
// The process to convert the MAC is as follows:
// 1) Split the MAC address (eg: 00:15:2b:e4:9b:60) in the middle.
// 00:15:2b <==> e4:9b:60
//
// 2) Insert ff:fe in the middle.
// 0015:2bff:fee4:9b60
//
// 3) Convert the first eight bits to binary.
// 00 -> 00000000
//
// 4) Invert the 7th bit.
// 00000000 -> 00000010
//
// 5) Convert these first eight bits back into hex.
// 00000010 -> 02, which yields an EUI-64 address of 0215:2bff:fee4:9b60
fn eui48_to_eui64(eui48: &[u8]) -> Vec<u8> {
    vec![
        eui48[0],
        eui48[1] ^ 0x02, // reverses the 7th bit from the 1st octect
        eui48[2],
        eui48[3],
        eui48[4],
        eui48[5],
        15,
        15,
        15,
        14,
        eui48[6],
        eui48[7],
        eui48[8],
        eui48[9],
        eui48[10],
        eui48[11],
    ]
}

/// Format a MAC address into the desired format
/// examples:
///  format_mac(&self.eui48, "", 0) // 001122aabbcc
///  format_mac(&self.eui48, "-", 2) // 00-11-22-aa-bb-cc
///  format_mac(&self.eui48, ".", 4) // 0011.22aa.bbcc
fn format_mac(mac: &[u8], delimiter: &str, chunks: u8) -> String {
    match chunks {
        4 => mac
            .chunks_exact(4)
            .map(|c| format!("{:x}{:x}{:x}{:x}", c[0], c[1], c[2], c[3]))
            .collect::<Vec<String>>()
            .join(delimiter),
        2 => mac
            .chunks_exact(2)
            .map(|c| format!("{:x}{:x}", c[0], c[1]))
            .collect::<Vec<String>>()
            .join(delimiter),
        _ => mac.iter().map(|c| format!("{:x}", c)).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_macs() -> Vec<&'static str> {
        vec![
            "00:11:22:aa:bb:cc",
            "00-11-22-aa-bb-cc",
            "0011.22aa.bbcc",
            "001122aabbcc",
            "001122AABBCC",
            " 0011.22aa.bbcc ",
            "00 11 22 AA BB CC",
            "001122-AABBCC",
        ]
    }

    #[test]
    fn raw_mac_from_macs() {
        for m in test_macs() {
            let mac = MacAddress::parse(m).unwrap();
            assert_eq!(mac.raw(), "001122aabbcc".to_owned());
        }
    }

    #[test]
    fn eui_mac_from_macs() {
        for m in test_macs() {
            let mac = MacAddress::parse(m).unwrap();
            assert_eq!(mac.eui(), "00-11-22-aa-bb-cc".to_owned());
        }
    }

    #[test]
    fn hex_mac_from_macs() {
        for m in test_macs() {
            let mac = MacAddress::parse(m).unwrap();
            assert_eq!(mac.hex(), "00:11:22:aa:bb:cc".to_owned());
        }
    }

    #[test]
    fn dot_mac_from_macs() {
        for m in test_macs() {
            let mac = MacAddress::parse(m).unwrap();
            assert_eq!(mac.dot(), "0011.22aa.bbcc".to_owned());
        }
    }

    #[test]
    fn octets_mac_from_macs() {
        for m in test_macs() {
            let mac = MacAddress::parse(m).unwrap();
            assert_eq!(mac.octets(), vec!["00", "11", "22", "aa", "bb", "cc"]);
        }
    }

    #[test]
    fn bits_mac_from_macs() {
        for m in test_macs() {
            let mac = MacAddress::parse(m).unwrap();
            assert_eq!(
                mac.bits(),
                vec![
                    "0000", "0000", "0001", "0001", "0010", "0010", "1010", "1010", "1011", "1011",
                    "1100", "1100"
                ]
            );
        }
    }

    #[test]
    fn binary_mac_from_macs() {
        for m in test_macs() {
            let mac = MacAddress::parse(m).unwrap();
            assert_eq!(
                mac.binary(),
                "000000000001000100100010101010101011101111001100"
            );
        }
    }

    #[test]
    fn oui_from_macs() {
        for m in test_macs() {
            let mac = MacAddress::parse(m).unwrap();
            assert_eq!(mac.oui(), "001122".to_owned());
        }
    }

    #[test]
    fn nic_from_macs() {
        for m in test_macs() {
            let mac = MacAddress::parse(m).unwrap();
            assert_eq!(mac.nic(), "aabbcc".to_owned());
        }
    }

    #[test]
    fn parse_invalid_length_mac() {
        let address = "bgf";
        let mac = MacAddress::parse(address).unwrap_err();
        assert_eq!(MacAddressError::InvalidLength(address.to_owned()), mac);
    }

    #[test]
    fn parse_invalid_mac() {
        let address = "xy-z1-23-bg-t7-89";
        let mac = MacAddress::parse(address).unwrap_err();
        assert_eq!(MacAddressError::InvalidMac(address.to_owned()), mac);
    }

    #[test]
    fn is_broadcast_mac() {
        let test_cases = vec![("ffffffffffff", true), ("001122aabbcc", false)];
        for tc in test_cases {
            let mac = MacAddress::parse(tc.0).unwrap();
            assert!(mac.is_broadcast() == tc.1)
        }
    }

    #[test]
    fn is_multicast_mac() {
        let test_cases = vec![("01005eaabbcc", true), ("001122aabbcc", false)];
        for tc in test_cases {
            let mac = MacAddress::parse(tc.0).unwrap();
            assert!(mac.is_multicast() == tc.1)
        }
    }

    #[test]
    fn is_unicast_mac() {
        let test_cases = vec![
            ("001122aabbcc", true),
            ("01005eaabbcc", false),
            ("ffffffffffff", false),
        ];
        for tc in test_cases {
            let mac = MacAddress::parse(tc.0).unwrap();
            assert!(mac.is_unicast() == tc.1)
        }
    }

    #[test]
    fn is_universal_mac() {
        let test_cases = vec![
            ("001122aabbcc", true),
            ("01005eaabbcc", true),
            ("ffffffffffff", false),
            ("02005eaabbcc", false),
        ];
        for tc in test_cases {
            let mac = MacAddress::parse(tc.0).unwrap();
            assert!(mac.is_universal() == tc.1)
        }
    }

    #[test]
    fn is_local_mac() {
        let test_cases = vec![
            ("001122aabbcc", false),
            ("01005eaabbcc", false),
            ("ffffffffffff", true),
            ("02005eaabbcc", true),
        ];
        for tc in test_cases {
            let mac = MacAddress::parse(tc.0).unwrap();
            assert!(mac.is_local() == tc.1)
        }
    }

    #[test]
    fn eui64_0_to_1() {
        let mac = MacAddress::parse("001122aabbcc").unwrap();
        assert_eq!(mac.eui64(), "02-11-22-ff-fe-aa-bb-cc".to_owned());
    }

    #[test]
    fn eui64_1_to_0() {
        let mac = MacAddress::parse("021122aabbcc").unwrap();
        assert_eq!(mac.eui64(), "00-11-22-ff-fe-aa-bb-cc".to_owned());
    }

    #[test]
    fn ipv6_link_local_0_to_1() {
        let mac = MacAddress::parse("001122aabbcc").unwrap();
        assert_eq!(
            mac.ipv6_link_local(),
            "fe80::0211:22ff:feaa:bbcc".to_owned()
        );
    }

    #[test]
    fn ipv6_link_local_1_to_0() {
        let mac = MacAddress::parse("021122aabbcc").unwrap();
        assert_eq!(
            mac.ipv6_link_local(),
            "fe80::0011:22ff:feaa:bbcc".to_owned()
        );
    }
}
