use core::str::FromStr;

use encoding_rs::mem::convert_latin1_to_utf8;

use crate::EncodingError;

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum Error {
    #[error("Unsupported string encoding")]
    UnsupportedEncoding(StringEncoding),
}

#[derive(Debug, Clone, PartialEq, Copy)]
pub enum StringEncoding {
    UTF8,
    DBCS(u16),
    JIS,
    UCS4,
    UCS2,
    ISO88591,
}

impl StringEncoding {
    pub fn decode(data: &[u8]) -> Result<(StringEncoding, usize), EncodingError> {
        match data[0] {
            0x00 => Ok((StringEncoding::UTF8, 1)),
            0x01 if data.len() >= 3 => Ok((
                StringEncoding::DBCS(u16::from_be_bytes([data[1], data[2]])),
                3,
            )),
            0x02 => Ok((StringEncoding::JIS, 1)),
            0x03 => Ok((StringEncoding::UCS4, 1)),
            0x04 => Ok((StringEncoding::UCS2, 1)),
            0x05 => Ok((StringEncoding::ISO88591, 1)),
            _ => Err(EncodingError::ValueOutOfRange),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            StringEncoding::UTF8 => vec![0x00],
            StringEncoding::DBCS(code) => {
                let mut data = code.to_be_bytes().to_vec();
                data.insert(0, 0x01);
                data
            }
            StringEncoding::JIS => vec![0x02],
            StringEncoding::UCS4 => vec![0x03],
            StringEncoding::UCS2 => vec![0x04],
            StringEncoding::ISO88591 => vec![0x05],
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CharacterString {
    pub encoding: StringEncoding,
    pub data: Vec<u8>,
}

impl Default for CharacterString {
    fn default() -> Self {
        Self {
            encoding: StringEncoding::UTF8,
            data: Vec::new(),
        }
    }
}

impl CharacterString {
    pub fn new(encoding: StringEncoding, data: Vec<u8>) -> Self {
        Self { encoding, data }
    }

    pub fn decode(data: &[u8]) -> Result<Self, EncodingError> {
        let (encoding, offset) = StringEncoding::decode(data)?;
        let data = data[offset..].to_vec();
        Ok(Self { encoding, data })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut data = self.encoding.encode();
        data.extend_from_slice(&self.data);
        data
    }

    pub fn to_string(&self) -> Result<String, Error> {
        match self.encoding {
            StringEncoding::UTF8 => Ok(String::from_utf8_lossy(&self.data).to_string()),
            StringEncoding::UCS2 => {
                let u16_data = self
                    .data
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes(c.try_into().unwrap()))
                    .collect::<Vec<_>>();
                Ok(String::from_utf16_lossy(&u16_data))
            }
            StringEncoding::ISO88591 => {
                let mut utf8_data = Vec::with_capacity(self.data.len() * 2);
                convert_latin1_to_utf8(&self.data, &mut utf8_data);
                Ok(String::from_utf8_lossy(&utf8_data).to_string())
            }
            _ => Err(Error::UnsupportedEncoding(self.encoding)),
        }
    }
}

impl FromStr for CharacterString {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            encoding: StringEncoding::UTF8,
            data: s.as_bytes().to_vec(),
        })
    }
}
