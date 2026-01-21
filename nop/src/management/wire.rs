// This file is part of the product NoPressure.
// SPDX-FileCopyrightText: 2025-2026 Zivatar Limited
// SPDX-License-Identifier: AGPL-3.0-or-later
// The code and documentation in this repository is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See LICENSE.

use std::error::Error;
use std::fmt;

pub type WireResult<T> = Result<T, WireError>;

#[derive(Debug)]
pub struct WireError {
    message: String,
}

impl WireError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "wire error: {}", self.message)
    }
}

impl Error for WireError {}

pub trait WireEncode {
    fn encode(&self, writer: &mut WireWriter) -> WireResult<()>;
}

pub trait WireDecode: Sized {
    fn decode(reader: &mut WireReader) -> WireResult<Self>;
}

#[derive(Debug, Clone, Copy)]
pub enum OptionWidth {
    U8,
    U16,
    U32,
    U64,
}

impl OptionWidth {
    fn for_count(count: usize) -> WireResult<Self> {
        match count {
            0 => Err(WireError::new("Option map requires at least one field")),
            1..=8 => Ok(OptionWidth::U8),
            9..=16 => Ok(OptionWidth::U16),
            17..=32 => Ok(OptionWidth::U32),
            33..=64 => Ok(OptionWidth::U64),
            _ => Err(WireError::new("Option map exceeds 64 fields")),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct OptionMap {
    width: OptionWidth,
    value: u64,
}

impl OptionMap {
    pub fn from_flags(flags: &[bool]) -> WireResult<Self> {
        let width = OptionWidth::for_count(flags.len())?;
        let mut value = 0u64;
        for (index, enabled) in flags.iter().enumerate() {
            if *enabled {
                value |= 1u64 << index;
            }
        }
        Ok(Self { width, value })
    }

    pub fn write(&self, writer: &mut WireWriter) -> WireResult<()> {
        match self.width {
            OptionWidth::U8 => writer.write_u8(self.value as u8),
            OptionWidth::U16 => writer.write_u16(self.value as u16),
            OptionWidth::U32 => writer.write_u32(self.value as u32),
            OptionWidth::U64 => writer.write_u64(self.value),
        }
        Ok(())
    }

    pub fn read(reader: &mut WireReader, count: usize) -> WireResult<Vec<bool>> {
        if count == 0 {
            return Ok(Vec::new());
        }
        let width = OptionWidth::for_count(count)?;
        let value = match width {
            OptionWidth::U8 => reader.read_u8()? as u64,
            OptionWidth::U16 => reader.read_u16()? as u64,
            OptionWidth::U32 => reader.read_u32()? as u64,
            OptionWidth::U64 => reader.read_u64()?,
        };

        let mask = if count == 64 {
            u64::MAX
        } else {
            (1u64 << count) - 1
        };
        if value & !mask != 0 {
            return Err(WireError::new("Option map contains unknown bits"));
        }

        let mut flags = Vec::with_capacity(count);
        for index in 0..count {
            flags.push((value >> index) & 1 == 1);
        }
        Ok(flags)
    }
}

#[derive(Debug, Default)]
pub struct WireWriter {
    buffer: Vec<u8>,
}

impl WireWriter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }

    pub fn write_u8(&mut self, value: u8) {
        self.buffer.push(value);
    }

    pub fn write_u16(&mut self, value: u16) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_u32(&mut self, value: u32) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_u64(&mut self, value: u64) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_i32(&mut self, value: i32) {
        self.buffer.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_bool(&mut self, value: bool) {
        self.write_u8(if value { 1 } else { 0 });
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) -> WireResult<()> {
        let len = u32::try_from(bytes.len())
            .map_err(|_| WireError::new("Byte slice exceeds u32 length limit"))?;
        self.write_u32(len);
        self.buffer.extend_from_slice(bytes);
        Ok(())
    }

    pub fn write_string(&mut self, value: &str) -> WireResult<()> {
        self.write_bytes(value.as_bytes())
    }

    pub fn write_vec<T, F>(&mut self, values: &[T], mut write_item: F) -> WireResult<()>
    where
        F: FnMut(&mut WireWriter, &T) -> WireResult<()>,
    {
        let len = u32::try_from(values.len())
            .map_err(|_| WireError::new("Vector length exceeds u32 limit"))?;
        self.write_u32(len);
        for value in values {
            write_item(self, value)?;
        }
        Ok(())
    }
}

pub struct WireReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> WireReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub fn ensure_fully_consumed(&self) -> WireResult<()> {
        if self.offset != self.bytes.len() {
            return Err(WireError::new("Trailing bytes after decode"));
        }
        Ok(())
    }

    pub fn read_u8(&mut self) -> WireResult<u8> {
        self.ensure_available(1)?;
        let value = self.bytes[self.offset];
        self.offset += 1;
        Ok(value)
    }

    pub fn read_u16(&mut self) -> WireResult<u16> {
        self.ensure_available(2)?;
        let value = u16::from_le_bytes([self.bytes[self.offset], self.bytes[self.offset + 1]]);
        self.offset += 2;
        Ok(value)
    }

    pub fn read_u32(&mut self) -> WireResult<u32> {
        self.ensure_available(4)?;
        let value = u32::from_le_bytes([
            self.bytes[self.offset],
            self.bytes[self.offset + 1],
            self.bytes[self.offset + 2],
            self.bytes[self.offset + 3],
        ]);
        self.offset += 4;
        Ok(value)
    }

    pub fn read_u64(&mut self) -> WireResult<u64> {
        self.ensure_available(8)?;
        let value = u64::from_le_bytes([
            self.bytes[self.offset],
            self.bytes[self.offset + 1],
            self.bytes[self.offset + 2],
            self.bytes[self.offset + 3],
            self.bytes[self.offset + 4],
            self.bytes[self.offset + 5],
            self.bytes[self.offset + 6],
            self.bytes[self.offset + 7],
        ]);
        self.offset += 8;
        Ok(value)
    }

    pub fn read_i32(&mut self) -> WireResult<i32> {
        self.ensure_available(4)?;
        let value = i32::from_le_bytes([
            self.bytes[self.offset],
            self.bytes[self.offset + 1],
            self.bytes[self.offset + 2],
            self.bytes[self.offset + 3],
        ]);
        self.offset += 4;
        Ok(value)
    }

    pub fn read_bool(&mut self) -> WireResult<bool> {
        let value = self.read_u8()?;
        match value {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(WireError::new("Invalid boolean value")),
        }
    }

    pub fn read_bytes(&mut self) -> WireResult<Vec<u8>> {
        let len = self.read_u32()? as usize;
        self.ensure_available(len)?;
        let slice = self.bytes[self.offset..self.offset + len].to_vec();
        self.offset += len;
        Ok(slice)
    }

    pub fn read_string(&mut self) -> WireResult<String> {
        let bytes = self.read_bytes()?;
        String::from_utf8(bytes).map_err(|_| WireError::new("Invalid UTF-8 string"))
    }

    pub fn read_vec<T, F>(&mut self, mut read_item: F) -> WireResult<Vec<T>>
    where
        F: FnMut(&mut WireReader<'a>) -> WireResult<T>,
    {
        let len = self.read_u32()? as usize;
        let mut values = Vec::with_capacity(len);
        for _ in 0..len {
            values.push(read_item(self)?);
        }
        Ok(values)
    }

    fn ensure_available(&self, len: usize) -> WireResult<()> {
        if self.offset + len > self.bytes.len() {
            return Err(WireError::new("Unexpected end of buffer"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_writer_reader_roundtrip() {
        let mut writer = WireWriter::new();
        writer.write_u8(7);
        writer.write_u16(500);
        writer.write_u32(42);
        writer.write_u64(123456);
        writer.write_i32(-12);
        writer.write_bool(true);
        writer.write_string("hi").expect("string");
        writer
            .write_vec(&["a", "b"], |w, value| w.write_string(value))
            .expect("vec");

        let bytes = writer.into_bytes();
        let mut reader = WireReader::new(&bytes);
        assert_eq!(reader.read_u8().unwrap(), 7);
        assert_eq!(reader.read_u16().unwrap(), 500);
        assert_eq!(reader.read_u32().unwrap(), 42);
        assert_eq!(reader.read_u64().unwrap(), 123456);
        assert_eq!(reader.read_i32().unwrap(), -12);
        assert!(reader.read_bool().unwrap());
        assert_eq!(reader.read_string().unwrap(), "hi");
        let values = reader.read_vec(|r| r.read_string()).expect("read vec");
        assert_eq!(values, vec!["a".to_string(), "b".to_string()]);
        reader.ensure_fully_consumed().expect("fully consumed");
    }

    #[test]
    fn option_map_roundtrip() {
        let flags = [true, false, true];
        let option_map = OptionMap::from_flags(&flags).expect("option map");
        let mut writer = WireWriter::new();
        option_map.write(&mut writer).expect("write option map");
        let bytes = writer.into_bytes();
        let mut reader = WireReader::new(&bytes);
        let decoded = OptionMap::read(&mut reader, flags.len()).expect("read option map");
        assert_eq!(decoded, flags);
    }

    #[test]
    fn option_map_rejects_unknown_bits() {
        let mut writer = WireWriter::new();
        writer.write_u8(0b0000_0100);
        let bytes = writer.into_bytes();
        let mut reader = WireReader::new(&bytes);
        let err = OptionMap::read(&mut reader, 2).unwrap_err();
        assert!(err.to_string().contains("unknown bits"));
    }

    #[test]
    fn read_bool_rejects_invalid_value() {
        let mut writer = WireWriter::new();
        writer.write_u8(2);
        let bytes = writer.into_bytes();
        let mut reader = WireReader::new(&bytes);
        let err = reader.read_bool().unwrap_err();
        assert!(err.to_string().contains("Invalid boolean"));
    }
}
