use std::convert::AsRef;



pub const TAP_PROTOCOL_CC:u8 = 1;
pub const TAP_PROTOCOL_ETH:u8 = 2;
pub const TAP_PROTOCOL_REPORT:u8 = 3;

pub const TAP_PROTOCOL_HEADER_SIZE:u8 = 5;



#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct TapPacketHeader {
    pub protocol: u8,
    pub size: u32
}


impl TapPacketHeader {
    pub fn new(protocol: u8, size: u32) -> Self {
        Self {
            protocol: protocol,
            size: size
        }
    }

    pub fn from_slice_as_mut(buf: &mut [u8]) -> &mut Self {
        let (head, body, _tail) = unsafe { buf.align_to_mut::<Self>() };
        assert!(head.is_empty(), "Data was not aligned");
        return &mut body[0];
    }

    pub fn from_slice_as_ref(buf: &[u8]) -> &Self {
        let (head, body, _tail) = unsafe { buf.align_to::<Self>() };
        assert!(head.is_empty(), "Data was not aligned");
        return &body[0];
    }
}

impl AsRef<[u8]> for TapPacketHeader {
    fn as_ref(&self) -> &[u8] {
        unsafe {
            ::std::slice::from_raw_parts(
                (self as *const _) as *const u8,
                ::std::mem::size_of::<TapPacketHeader>(),
                )
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::BorrowMut;
    use crypto::{symmetriccipher::SynchronousStreamCipher, rc4::Rc4};


    #[test]
    fn it_works() {
        let mut v = vec![0u8; 5];
        {
            let packet = TapPacketHeader::from_slice_as_mut(& mut v);
            packet.protocol = 1;
            packet.size = 32;
        }
        println!("xxxxx {:#x?}", &v);

        assert_eq!(1, v[0]);

        let key = "123456";
        let input = "56789";

        let mut rc4 = Rc4::new(key.as_bytes());
        let mut result = vec![0u8;input.len()];

        rc4.process(input.as_bytes(), & mut result);

        let mut result2 = vec![0u8;result.len()];

        let mut rc42 = Rc4::new(key.as_bytes());
        rc42.process(&result, & mut result2);

        let output = String::from_utf8(result2).unwrap();
        println!("output {}", &output);
        assert_eq!(input, &output);


    }
}


