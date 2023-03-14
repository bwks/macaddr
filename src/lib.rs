use regex::Regex;

const BROADCAST_MAC: &str = "ffffffffffff";
const MULTICAST_MAC: &str = "01005e";

#[derive(Debug, PartialEq)]
pub enum MacAddressError {
    InvalidLength(String),
    InvalidMac(String),
    RegexError(String),
}

impl std::fmt::Display for MacAddressError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MacAddressError::InvalidLength(a) => {
                write!(f, "address: `{a}` is not 12 characters long")
            }
            MacAddressError::InvalidMac(a) => write!(f, "address: `{a}` is not a MAC adddress"),
            MacAddressError::RegexError(a) => write!(f, "error parsing regex for address: `{a}`"),
        }
    }
}

#[derive(Debug)]
pub struct MacAddress {
    address: String,
}

impl MacAddress {
    pub fn parse(address: &str) -> Result<Self, MacAddressError> {
        // matches 12x HEX chars
        let re = match Regex::new(r"^[a-f0-9]{12}$") {
            Ok(r) => r,
            Err(_) => return Err(MacAddressError::RegexError(address.to_owned())),
        };

        // get bare address by removing known MAC delimiters
        let bare = address
            .trim()
            .replace([':', '-', '.', ' '], "")
            .to_lowercase();

        // confirm address length == 12
        if bare.chars().count() != 12 {
            return Err(MacAddressError::InvalidLength(address.to_owned()));
        }

        // confirm address is made up of HEX chars
        if !re.is_match(&bare) {
            return Err(MacAddressError::InvalidMac(address.to_owned()));
        }

        Ok(Self { address: bare })
    }

    pub fn bare(&self) -> String {
        self.address.to_owned()
    }

    pub fn eui(&self) -> String {
        let chars: Vec<char> = self.address.chars().collect();
        format!(
            "{}{}-{}{}-{}{}-{}{}-{}{}-{}{}",
            chars[0],
            chars[1],
            chars[2],
            chars[3],
            chars[4],
            chars[5],
            chars[6],
            chars[7],
            chars[8],
            chars[9],
            chars[10],
            chars[11],
        )
    }

    pub fn hex(&self) -> String {
        let chars: Vec<char> = self.address.chars().collect();
        format!(
            "{}{}:{}{}:{}{}:{}{}:{}{}:{}{}",
            chars[0],
            chars[1],
            chars[2],
            chars[3],
            chars[4],
            chars[5],
            chars[6],
            chars[7],
            chars[8],
            chars[9],
            chars[10],
            chars[11],
        )
    }

    pub fn dot(&self) -> String {
        let chars: Vec<char> = self.address.chars().collect();
        format!(
            "{}{}{}{}.{}{}{}{}.{}{}{}{}",
            chars[0],
            chars[1],
            chars[2],
            chars[3],
            chars[4],
            chars[5],
            chars[6],
            chars[7],
            chars[8],
            chars[9],
            chars[10],
            chars[11],
        )
    }

    pub fn octets(&self) -> Vec<String> {
        self.eui().split('-').map(|s| s.to_string()).collect()
    }

    pub fn bits(&self) -> Vec<String> {
        self.bare().chars().map(hex_to_binary).collect()
    }

    pub fn binary(&self) -> String {
        self.bits().join("")
    }

    pub fn oui(&self) -> String {
        let v: Vec<String> = self.bare().chars().map(|s| s.to_string()).collect();
        v[0..=5].join("")
    }

    pub fn nic(&self) -> String {
        let v: Vec<String> = self.bare().chars().map(|s| s.to_string()).collect();
        v[6..=11].join("")
    }

    pub fn is_broadcast(&self) -> bool {
        self.bare() == BROADCAST_MAC
    }

    pub fn is_multicast(&self) -> bool {
        self.oui() == MULTICAST_MAC
    }

    pub fn is_unicast(&self) -> bool {
        match self.is_broadcast() || self.is_multicast() {
            true => false,
            false => true,
        }
    }

    pub fn eui64(&self) -> String {
        invert_ul(self)
    }

    pub fn ipv6_link_local(&self) -> String {
        format!("fe80{}", self.eui64())
    }
}

impl std::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.bare())
    }
}

fn hex_to_binary(c: char) -> String {
    let s = match c {
        '0' => "0000",
        '1' => "0001",
        '2' => "0010",
        '3' => "0011",
        '4' => "0100",
        '5' => "0101",
        '6' => "0110",
        '7' => "0111",
        '8' => "1000",
        '9' => "1001",
        'a' => "1010",
        'b' => "1011",
        'c' => "1100",
        'd' => "1101",
        'e' => "1110",
        'f' => "1111",
        _ => "",
    };
    s.to_owned()
}

fn binary_to_hex(s: &str) -> char {
    match s {
        "0000" => '0',
        "0001" => '1',
        "0010" => '2',
        "0011" => '3',
        "0100" => '4',
        "0101" => '5',
        "0110" => '6',
        "0111" => '7',
        "1000" => '8',
        "1001" => '9',
        "1010" => 'a',
        "1011" => 'b',
        "1100" => 'c',
        "1101" => 'd',
        "1110" => 'e',
        "1111" => 'f',
        _ => ' ',
    }
}

// Returns a MAC address with the Universal/Local (U/L)
// Bit inverted. The U/L bit is the 7th but in the first octet.
// Reference RFC: http://www.faqs.org/rfcs/rfc2373.html
//
// The process to convert the MAC is as follows:
// 1) Split the MAC address in the middle.
// 00:15:2b <==> e4:9b:60
//
// 2) Insert ff:fe in the middle.
// 00:15:2b:ff:fe:e4:9b:60
//
// 3) Convert the first eight bits to binary.
// 00 -> 00000000
//
// 4) Invert the 7th bit.
// 00000000 -> 00000010
//
// 5) Convert these first eight bits back into hex.
// 00000010 -> 02, which yields an EUI-64 address of 02:15:2b:ff:fe:e4:9b:60
fn invert_ul(mac: &MacAddress) -> String {
    let mut bits = mac.bits();
    let mut flipped_bit: Vec<String> = bits[1].chars().map(|i| i.to_string()).collect();

    match flipped_bit[2] == "0" {
        true => flipped_bit[2] = "1".to_owned(),
        false => flipped_bit[2] = "0".to_owned(),
    };

    bits[1] = flipped_bit.join("");

    let hex: Vec<char> = bits.iter().map(|s| binary_to_hex(s)).collect();

    format!(
        "{}{}{}{}{}{}fffe{}",
        hex[0],
        hex[1],
        hex[2],
        hex[3],
        hex[4],
        hex[5],
        mac.nic()
    )
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
        ]
    }

    #[test]
    fn bare_mac_from_macs() {
        for m in test_macs() {
            let mac = MacAddress::parse(m).unwrap();
            assert_eq!(mac.bare(), "001122aabbcc".to_owned());
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
    fn eui64_0_to_1() {
        let mac = MacAddress::parse("001122aabbcc").unwrap();
        assert_eq!(mac.eui64(), "021122fffeaabbcc".to_owned());
    }

    #[test]
    fn eui64_1_to_0() {
        let mac = MacAddress::parse("021122aabbcc").unwrap();
        assert_eq!(mac.eui64(), "001122fffeaabbcc".to_owned());
    }

    #[test]
    fn ipv6_link_local_0_to_1() {
        let mac = MacAddress::parse("001122aabbcc").unwrap();
        assert_eq!(mac.ipv6_link_local(), "fe80021122fffeaabbcc".to_owned());
    }

    #[test]
    fn ipv6_link_local_1_to_0() {
        let mac = MacAddress::parse("021122aabbcc").unwrap();
        assert_eq!(mac.ipv6_link_local(), "fe80001122fffeaabbcc".to_owned());
    }
}
