use std::io;

use io::Write;

use arrow_array::Int32Array;

use arrow_array::RecordBatch;

use arrow_array::ArrayRef;
use arrow_array::cast::AsArray;

use zrip::FrameEncoder;

pub const FRAME_HEADER_SKIP: u32 = 0x184d_2a5e;

pub const MAGIC_NO: u32 = 0x8f92_eab1;

pub const FLAG_NO_CHECKSUM: u8 = 0;

#[derive(Debug, PartialEq, Eq)]
pub struct SeekTable {
    pub compressed_size: u32,
    pub original_size: u32,
}

pub fn int2writer<W>(i: u32, wtr: &mut W) -> Result<(), io::Error>
where
    W: Write,
{
    let encoded: [u8; 4] = i.to_le_bytes();
    wtr.write_all(&encoded)
}

impl SeekTable {
    pub fn to_writer<W>(&self, wtr: &mut W) -> Result<(), io::Error>
    where
        W: Write,
    {
        int2writer(self.compressed_size, wtr)?;
        int2writer(self.original_size, wtr)?;
        Ok(())
    }
}

impl SeekTable {
    pub fn write_trailer<W>(tabs: &[Self], wtr: &mut W) -> Result<(), io::Error>
    where
        W: Write,
    {
        let sz: u32 = tabs.len() as u32;
        int2writer(sz, wtr)?;
        wtr.write_all(&[FLAG_NO_CHECKSUM])?;
        int2writer(MAGIC_NO, wtr)?;
        wtr.flush()
    }
}

impl SeekTable {
    pub fn write_header<W>(tabs: &[Self], wtr: &mut W) -> Result<(), io::Error>
    where
        W: Write,
    {
        let cnt: u32 = tabs.len() as u32;
        let sz: u32 = 9 + 8 * cnt; // the size of the trailer + total table size
        int2writer(FRAME_HEADER_SKIP, wtr)?;
        int2writer(sz, wtr)?;
        Ok(())
    }
}

impl SeekTable {
    pub fn write_all<W>(tabs: &[Self], wtr: &mut W) -> Result<(), io::Error>
    where
        W: Write,
    {
        Self::write_header(tabs, wtr)?;
        for tab in tabs {
            tab.to_writer(wtr)?;
        }
        Self::write_trailer(tabs, wtr)?;
        Ok(())
    }
}

pub fn ints2wtr_generic<W>(ints: &Int32Array, wtr: &mut W) -> Result<(), io::Error>
where
    W: Write,
{
    for i in ints.values() {
        let val: i32 = *i;
        int2writer(val as u32, wtr)?;
    }
    Ok(())
}

#[cfg(target_endian = "little")]
pub fn ints2wtr4le<W>(ints: &Int32Array, wtr: &mut W) -> Result<(), io::Error>
where
    W: Write,
{
    let s: &[u8] = ints.values().inner().as_slice();
    wtr.write_all(s)
}

#[cfg(target_endian = "little")]
pub fn ints2wtr<W>(ints: &Int32Array, wtr: &mut W) -> Result<(), io::Error>
where
    W: Write,
{
    ints2wtr4le(ints, wtr)
}

#[cfg(not(target_endian = "little"))]
pub fn ints2wtr<W>(ints: &Int32Array, wtr: &mut W) -> Result<(), io::Error>
where
    W: Write,
{
    ints2wtr_generic(ints, wtr)
}

pub struct CompressionLevel(i32);

impl CompressionLevel {
    pub const FAST7: Self = Self(-7);
    pub const FAST6: Self = Self(-6);
    pub const FAST5: Self = Self(-5);
    pub const FAST4: Self = Self(-4);
    pub const FAST3: Self = Self(-3);
    pub const FAST2: Self = Self(-2);
    pub const FAST1: Self = Self(-1);

    pub const DEFAULT: Self = Self(0);

    pub const BEST1: Self = Self(1);
    pub const BEST2: Self = Self(2);
    pub const BEST3: Self = Self(3);
    pub const BEST4: Self = Self(4);
}

impl CompressionLevel {
    pub fn as_int(&self) -> i32 {
        self.0
    }
}

impl CompressionLevel {
    pub fn ints2buf(&self, ints: &Int32Array, buf: &mut Vec<u8>) -> Result<SeekTable, io::Error> {
        buf.clear();

        let sz: usize = ints.len();
        let mut enc: FrameEncoder<&mut Vec<u8>> =
            FrameEncoder::new(buf, self.as_int()).map_err(io::Error::other)?;
        ints2wtr(ints, &mut enc)?;
        enc.flush()?;
        let inner: &mut Vec<u8> = enc.finish()?;
        let compressed_size: u32 = inner.len() as u32;
        let original_size: u32 = (sz << 2) as u32;
        Ok(SeekTable {
            compressed_size,
            original_size,
        })
    }
}

impl CompressionLevel {
    pub fn recs2wtr<I, W>(
        &self,
        recs: I,
        wtr: &mut W,
        colix: usize,
        tabs: &mut Vec<SeekTable>,
    ) -> Result<(), io::Error>
    where
        I: Iterator<Item = Result<RecordBatch, io::Error>>,
        W: Write,
    {
        tabs.clear();

        let mut buf: Vec<u8> = vec![];
        for rslt in recs {
            let rbat: RecordBatch = rslt?;
            let cols: &[ArrayRef] = rbat.columns();
            let ocol: Option<&ArrayRef> = cols.get(colix);
            let Some(col) = ocol else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid column index: out of range",
                ));
            };

            let oints: Option<&Int32Array> = col.as_primitive_opt();
            let Some(ints) = oints else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid column: expected Int32Array",
                ));
            };

            let tab: SeekTable = self.ints2buf(ints, &mut buf)?;
            wtr.write_all(&buf)?;
            tabs.push(tab);
        }
        Ok(())
    }
}

impl CompressionLevel {
    pub fn recs2zeek2wtr<I, W>(
        &self,
        recs: I,
        wtr: &mut W,
        colix: usize,
        tabs: &mut Vec<SeekTable>,
    ) -> Result<(), io::Error>
    where
        I: Iterator<Item = Result<RecordBatch, io::Error>>,
        W: Write,
    {
        self.recs2wtr(recs, wtr, colix, tabs)?;
        SeekTable::write_all(tabs, wtr)?;
        Ok(())
    }
}
