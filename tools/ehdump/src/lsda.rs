// This file is mostly adapted from Theseus (https://github.com/theseus-os/Theseus)
// original: https://github.com/theseus-os/Theseus/blob/theseus_main/kernel/unwind/src/lsda.rs
// Theseus is provided under the MIT license:
//
// The MIT License (MIT)
//
// Copyright (c) 2017 Kevin Boos
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! Routines for parsing the gcc-style LSDA (Language-Specific Data Area) in an ELF object file,
//! which corresponds to an area within a `.gcc_except_table` section.

use super::ArchPointerWidth;
use core::ops::Range;
use fallible_iterator::FallibleIterator;
use gimli::{constants::*, DwEhPe, EndianSlice, Endianity, Reader, ReaderOffset};
use log::{error, warn};

/// `GccExceptTableArea` contains the contents of the Language-Specific Data Area (LSDA)
/// that is used to locate cleanup (run destructors for) a given function during stack unwinding.
///
/// Though an object file typically only includes a single `.gcc_except_table` section, it may include multiple.
/// This struct represents only *one area* of that section, the area that is for cleaning up a single function.
/// There may exist multiple instances of this struct created as overlays
/// for different, non-overlapping areas of that one `.gcc_except_table` section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GccExceptTableArea<R: Reader> {
    reader: R,
    function_start_address: u64,
    pub arch_pointer_width: ArchPointerWidth,
}

impl<'input, Endian: Endianity> GccExceptTableArea<EndianSlice<'input, Endian>> {
    /// Construct a new `GccExceptTableArea` instance from the given input data,
    /// which is a slice that typically begins at an LSDA pointer that was fd
    /// from a `FrameDescriptionEntry` in the `EhFrame` section.
    ///
    /// The starting address of the function that it corresponds to must aso be provided,
    /// because this is often used as the default base address for the landing pad
    /// from which all offsets are calculated.
    pub fn new(
        data: &'input [u8],
        endian: Endian,
        function_start_address: u64,
        arch_pointer_width: ArchPointerWidth,
    ) -> Self {
        GccExceptTableArea {
            reader: EndianSlice::new(data, endian),
            function_start_address,
            arch_pointer_width,
        }
    }
}

impl<R: Reader> GccExceptTableArea<R> {
    /// Parses the .gcc_except_table entries from the very top of the LSDA area.
    /// This only parses the two headers that are guaranteed to exist,
    /// the other dynamically-sized entries should be parsed elsewhere using the result of this function.
    ///
    /// The flow of this code was partially inspired by rust's stdlib `libpanic_unwind/dwarf/eh.rs` file.
    /// <https://github.com/rust-lang/rust/blob/master/src/libpanic_unwind/dwarf/eh.rs>
    pub fn parse_from_beginning(&self) -> gimli::Result<(LsdaHeader, CallSiteTableHeader, R)> {
        // Clone the internal `Reader` to avoid modifying the offset position of the original provided reader.
        let mut reader = self.reader.clone();

        // First, parse the top-level header, which comes at the very beginning
        let lsda_header = LsdaHeader::parse(&mut reader, self.arch_pointer_width)?;
        // debug!("{:#X?}", lsda_header);

        // Second, parse the call site table header, which comes right after the top-level LSDA header
        let call_site_table_header =
            CallSiteTableHeader::parse(&mut reader, self.arch_pointer_width)?;
        // debug!("{:#X?}", call_site_table_header);

        Ok((lsda_header, call_site_table_header, reader))
    }

    /// Returns an iterator over all of the call site entries
    /// found in this area of this .gcc_except_table section.
    ///
    /// Can be used with the `FallibleIterator` trait.
    pub fn call_site_table_entries(&self) -> gimli::Result<CallSiteTableIterator<R>> {
        let (lsda_header, call_site_table_header, reader) = self.parse_from_beginning()?;
        // set up the call site table iterator so it knows when to stop parsing entries.
        let end_of_call_site_table = reader.offset_id().0 + call_site_table_header.length;

        Ok(CallSiteTableIterator {
            call_site_table_encoding: call_site_table_header.encoding,

            arch_pointer_width: self.arch_pointer_width,
            end_of_call_site_table,
            landing_pad_base: lsda_header
                .landing_pad_base
                .unwrap_or(self.function_start_address),
            reader,
        })
    }

    /// Iterates over the call site table and finds the entry that matches the given instruction pointer (IP),
    /// i.e., the entry that covers the range of addresses that the `ip` falls within.
    pub fn call_site_table_entry_for_address(
        &self,
        address: u64,
    ) -> gimli::Result<CallSiteTableEntry> {
        let mut iter = self.call_site_table_entries()?;
        while let Some(entry) = iter.next()? {
            if entry.range_of_covered_addresses().contains(&address) {
                return Ok(entry);
            }
        }
        Err(gimli::Error::NoUnwindInfoForAddress)
    }

    pub fn action_records_for_offset(&self, offset: u64) -> gimli::Result<ActionRecordIterator<R>> {
        ActionRecordIterator::new(&self, offset)
    }
    #[allow(dead_code)]
    pub fn type_table(&self) -> gimli::Result<TypeTable<R>> {
        TypeTable::new(&self)
    }
}

/// The header of an LSDA section, which is at the very beginning of the area
/// in the .gcc_except_table section that was pointed to by a stack frame's LSDA pointer.
#[derive(Debug)]
pub struct LsdaHeader {
    /// The encoding used to read the next value `landing_pad_base`.
    landing_pad_base_encoding: DwEhPe,
    /// If the above `landing_pad_base_encoding` is not `DW_EH_PE_omit`,
    /// then this is the value that should be used as the base address of the landing pad,
    /// which is used by all the offsets specified in the LSDA call site tables and action tables.
    /// It is decoded using the above `landing_pad_base_encoding`,
    /// which is typically the uleb128 encoding, but not always guaranteed to be.
    /// Otherwise, if `DW_EH_PE_omit`, the default value is the starting function address
    /// specified in the FDE (FrameDescriptionEntry) corresponding to this LSDA.
    ///
    /// Typically, this will be the virtual address of the function that this cleanup routine is for;
    /// such cleanup routines are usually at the end of the function's text section.
    landing_pad_base: Option<u64>,
    /// The encoding used to read pointer values in the type table.
    pub type_table_encoding: DwEhPe,
    /// If the above `type_table_encoding` is not `DW_EH_PE_omit`,
    /// this is the offset to the type table, starting from the end of this header.
    /// This is always encoded as a uleb128 value.
    /// If it was `DW_EH_PE_omit` above, then there is no type table,
    /// which is quite common in Rust-compiled object files.
    pub type_table_offset: Option<u64>,
}

impl LsdaHeader {
    fn parse<R: gimli::Reader>(
        reader: &mut R,
        arch_pointer_width: ArchPointerWidth,
    ) -> gimli::Result<LsdaHeader> {
        let lp_encoding = DwEhPe(reader.read_u8()?);
        let lp = if lp_encoding == DW_EH_PE_omit {
            None
        } else {
            Some(read_encoded_pointer(
                reader,
                lp_encoding,
                arch_pointer_width,
            )?)
        };

        let tt_encoding = match reader.read_u8()? {
            0xff => DW_EH_PE_omit,
            other => DwEhPe(other & 0xf),
        };

        let tt_offset = if tt_encoding == DW_EH_PE_omit {
            None
        } else {
            Some(read_encoded_pointer(
                reader,
                DW_EH_PE_uleb128,
                arch_pointer_width,
            )?)
        };

        Ok(LsdaHeader {
            landing_pad_base_encoding: lp_encoding,
            landing_pad_base: lp,
            type_table_encoding: tt_encoding,
            type_table_offset: tt_offset,
        })
    }
}

/// The header of the call site table, which defines the length of the table
/// and the encoding format used to parse address values in the table.
/// The call site table comes immediately after the `LsdaHeader`.
#[derive(Debug)]
pub struct CallSiteTableHeader {
    /// The encoding of items in the call site table.
    encoding: DwEhPe,
    /// The total length of the entire call site table, in bytes.
    /// This is always encoded in uleb128.
    length: u64,
}
impl CallSiteTableHeader {
    fn parse<R: gimli::Reader>(
        reader: &mut R,
        arch_pointer_width: ArchPointerWidth,
    ) -> gimli::Result<CallSiteTableHeader> {
        let encoding = DwEhPe(reader.read_u8()?);
        let length = read_encoded_pointer(reader, DW_EH_PE_uleb128, arch_pointer_width)?;
        Ok(CallSiteTableHeader { encoding, length })
    }
}

/// An entry in the call site table, which defines landing pad functions and additional actions
/// that should be executed when unwinding a given a stack frame.
/// The relevant entry for a particular stack frame can be found based on the range of addresses it covers.
#[derive(Debug)]
pub struct CallSiteTableEntry {
    /// An offset from the landing pad base address (top of function section)
    /// that specifies the first (starting) address that is covered by this entry.
    starting_offset: u64,
    /// The length (from the above `starting_offset`) that specifies
    /// the range of addresses covered by this entry.
    length: u64,
    /// The offset from the `landing_pad_base` at which the landing pad entry function exists.
    /// If `0`, then there is no landing pad function that should be run.
    landing_pad_offset: u64,
    /// The offset into the action table that specifies what additional action to undertake.
    /// If `0`, there is no action;
    /// otherwise, this value minus 1 (`action_offset - 1`) should be used to locate the action table entry.
    action_offset: u64,

    /// The starting address of the function that this GccExceptTableArea pertains to.
    /// This is not actually part of the table entry as defined in the gcc LSDA spec,
    /// it comes from the top-level LSDA header and is replicated here for convenience.
    landing_pad_base: u64,
}

impl CallSiteTableEntry {
    fn parse<R: gimli::Reader>(
        reader: &mut R,
        call_site_encoding: DwEhPe,
        arch_pointer_width: ArchPointerWidth,
        landing_pad_base: u64,
    ) -> gimli::Result<CallSiteTableEntry> {
        let cs_start = read_encoded_pointer(reader, call_site_encoding, arch_pointer_width)?;
        let cs_length = read_encoded_pointer(reader, call_site_encoding, arch_pointer_width)?;
        let cs_lp = read_encoded_pointer(reader, call_site_encoding, arch_pointer_width)?;
        let cs_action = read_encoded_pointer(reader, DW_EH_PE_uleb128, arch_pointer_width)?;
        Ok(CallSiteTableEntry {
            starting_offset: cs_start,
            length: cs_length,
            landing_pad_offset: cs_lp,
            action_offset: cs_action,
            landing_pad_base,
        })
    }

    /// The range of addresses (instruction pointers) that are covered by this entry.
    pub fn range_of_covered_addresses(&self) -> Range<u64> {
        //println!("{:?}", self);
        (self
            .landing_pad_base
            .overflowing_add(self.starting_offset)
            .0)
            ..(self
                .landing_pad_base
                .overflowing_add(self.starting_offset)
                .0
                .overflowing_add(self.length)
                .0)
    }

    /// The address of the actual landing pad, i.e., the cleanup routine that should run, if one exists.
    pub fn landing_pad_address(&self) -> Option<u64> {
        if self.landing_pad_offset == 0 {
            None
        } else {
            Some(self.landing_pad_base + self.landing_pad_offset)
        }
    }

    /// The offset into the action table that specifies which additional action should be undertaken
    /// when invoking this landing pad cleanup routine, if one exists.
    pub fn action_offset(&self) -> Option<u64> {
        if self.action_offset == 0 {
            // no action to perform
            None
        } else {
            // the gcc_except_table docs specify that 1 must be subtracted to the action offset if it is not zero.
            Some(self.action_offset - 1)
        }
    }
}

/// An iterator over all of the entries in a GccExceptTableArea's call site table.
///
/// Can be used with the `FallibleIterator` trait.
pub struct CallSiteTableIterator<R: Reader> {
    /// The encoding of pointers in the call site table.
    call_site_table_encoding: DwEhPe,

    arch_pointer_width: ArchPointerWidth,
    /// This is the ending bound for the following `reader` to parse,
    /// i.e., the reader offset right after the final call site table entry.
    end_of_call_site_table: u64,
    /// The starting address of the function that this GccExceptTableArea pertains to.
    landing_pad_base: u64,
    /// This reader must be queued up to the beginning of the first call site table entry,
    /// i.e., right after the end of the call site table header.
    reader: R,
}

impl<R: Reader> FallibleIterator for CallSiteTableIterator<R> {
    type Item = CallSiteTableEntry;
    type Error = gimli::Error;

    fn next(&mut self) -> Result<Option<Self::Item>, Self::Error> {
        if self.reader.offset_id().0 < self.end_of_call_site_table {
            let entry = CallSiteTableEntry::parse(
                &mut self.reader,
                self.call_site_table_encoding,
                self.arch_pointer_width,
                self.landing_pad_base,
            )?;
            if let Some(action_offset) = entry.action_offset() {
                #[cfg(not(downtime_eval))]
                warn!(
                    "unsupported/unhandled call site action, offset (with 1 added): {:#X}",
                    action_offset
                );
            }
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug)]
/// An iterator over action records, yielding all actions in a chain.
pub struct ActionRecordIterator<R: Reader> {
    // The offset of the next item in the action chain, or None if
    // no next action is specified.
    offset: Option<u64>,

    // A reader indexed to the beginning of the action record table.
    reader: R,

    arch_pointer_width: ArchPointerWidth,
}

impl<R: Reader> ActionRecordIterator<R> {
    pub fn new(gcc_except_table_area: &GccExceptTableArea<R>, offset: u64) -> gimli::Result<Self> {
        let (_, call_site_table_header, mut reader) =
            gcc_except_table_area.parse_from_beginning()?;

        // Skip to the end of the call site table header. This is where the action record table starts.
        reader.skip(<R as Reader>::Offset::from_u64(
            call_site_table_header.length,
        )?)?;

        Ok(Self {
            offset: Some(offset),
            reader,
            arch_pointer_width: gcc_except_table_area.arch_pointer_width,
        })
    }
}

impl<R: Reader> FallibleIterator for ActionRecordIterator<R> {
    type Item = ActionRecord;
    type Error = gimli::Error;

    fn next(&mut self) -> Result<Option<Self::Item>, Self::Error> {
        if self.offset.is_none() {
            return Ok(None);
        }

        let mut reader = self.reader.clone();
        let offset = self.offset.unwrap();

        reader.skip(<R as Reader>::Offset::from_u64(offset)?)?;

        let ar_filter =
            read_encoded_pointer(&mut reader, DW_EH_PE_sleb128, self.arch_pointer_width)? as i64;
        let ar_disp_base = reader.offset_id().0 - self.reader.offset_id().0;
        let ar_disp =
            read_encoded_pointer(&mut reader, DW_EH_PE_sleb128, self.arch_pointer_width)? as i64;

        let ar = ActionRecord { ar_filter, ar_disp };

        self.offset = match ar.ar_disp {
            0 => None,
            disp => Some((ar_disp_base as i64 + disp) as u64),
        };

        Ok(Some(ar))
    }
}

#[derive(Debug)]
/// An entry in the Action Record table.
pub struct ActionRecord {
    ///  Used by the runtime to match the type of the thrown exception to the type of
    /// the catch clauses or the types in the exception specification.
    ///
    /// A filter value of 0 indicates that there is a cleanup function to be executed.
    /// This is a reverse-index (starting at 1) into the type table.
    pub ar_filter: i64,

    /// Self-relative signed displacement in bytes to the next action record,
    /// or 0 if there is no next action record.
    pub ar_disp: i64,
}

/// Type table reference struct.
#[derive(Debug)]
#[allow(dead_code)]
pub struct TypeTable<R: Reader> {
    /// Type table encoding (was expecting DW_EH_PE_udata4 but that's not true)
    pub encoding: DwEhPe,

    // The offset from which the table starts (relative to the end of the LSDA header).
    pub offset: u64,

    // Reader indexed at the start of current lsda.
    pub lsda_begin_reader_id: u64,

    // A reader indexed at the end of the LSDA header.
    reader: R,

    arch_pointer_width: ArchPointerWidth,
}

impl<R: Reader> TypeTable<R> {
    pub fn new(gcc_except_table_area: &GccExceptTableArea<R>) -> gimli::Result<Self> {
        // Clone the internal `Reader` to avoid modifying the offset position of the original provided reader.
        let mut reader = gcc_except_table_area.reader.clone();

        // Get the id of the reader before parsing the LSDA header.
        let id = reader.offset_id().0;

        // First, parse the top-level header, which comes at the very beginning
        let lsda_header = LsdaHeader::parse(&mut reader, gcc_except_table_area.arch_pointer_width)?;

        // If TypeTable is missing just set offset to 0 and treat error in get_type.
        let offset = match lsda_header.type_table_offset {
            None => 0,
            Some(x) => x,
        };

        Ok(Self {
            offset: offset,
            // Type info seems to be encoded as .long
            encoding: lsda_header.type_table_encoding,
            lsda_begin_reader_id: id,
            reader,
            arch_pointer_width: gcc_except_table_area.arch_pointer_width,
        })
    }

    #[allow(dead_code)]
    pub fn get_type(&mut self, record: ActionRecord, lsda_ptr: u64) -> gimli::Result<Vec<u64>> {
        // Just return some error in case TypeTable is omitted
        if self.offset == 0 {
            return Err(gimli::Error::CannotParseOmitPointerEncoding);
        }

        let mut filters = Vec::new();

        if record.ar_filter == 0 {
            return Ok(filters);
        } else if record.ar_filter > 0 {
            filters.push(record.ar_filter as u64);
        } else {
            // For negative type filters first read the list of exceptioninfo
            // indexes which starts right after the type table.
            let mut index_reader = self.reader.clone();
            index_reader.skip(<R as Reader>::Offset::from_u64(
                self.offset + record.ar_filter.abs() as u64 - 1,
            )?)?;

            let mut index = index_reader.read_u8()?;

            while index != 0 {
                filters.push(index as u64);
                index = index_reader.read_u8()?;
            }
        }

        let ty_size = encoding_size(self.encoding, self.arch_pointer_width);
        // If encoding size is 0 then we had a problem parsing the encoding type.

        if ty_size == 0 {
            return Err(gimli::Error::UnknownPointerEncoding);
        }

        let mut type_info_vec = Vec::new();

        for filter in filters.into_iter() {
            let mut reader = self.reader.clone();

            let offset = self.offset - (ty_size * filter as u64);

            reader.skip(<R as Reader>::Offset::from_u64(offset)?)?;

            let base_disp = lsda_ptr + reader.offset_id().0 - self.lsda_begin_reader_id;

            let encoded_offset =
                read_encoded_pointer(&mut reader, self.encoding, self.arch_pointer_width);

            match encoded_offset {
                Ok(0) => type_info_vec.push(0),
                Ok(x) => type_info_vec.push((base_disp as i64 + x as i64) as u64),
                Err(x) => return Err(x),
            };
        }

        Ok(type_info_vec)
    }
}

/// Decodes the next pointer from the given `reader` (a stream of bytes) using the given `encoding` format.
#[allow(non_upper_case_globals)]
fn read_encoded_pointer<R: gimli::Reader>(
    reader: &mut R,
    encoding: DwEhPe,
    arch_pointer_width: ArchPointerWidth,
) -> gimli::Result<u64> {
    match encoding {
        DW_EH_PE_omit => Err(gimli::Error::CannotParseOmitPointerEncoding),
        DW_EH_PE_absptr => match arch_pointer_width {
            ArchPointerWidth::Width32Bit => reader.read_u64().map(|v| v as u64),
            ArchPointerWidth::Width64Bit => reader.read_u32().map(|v| v as u64),
        },
        DW_EH_PE_uleb128 => reader.read_uleb128().map(|v| v as u64),
        DW_EH_PE_udata2 => reader.read_u16().map(|v| v as u64),
        DW_EH_PE_udata4 => reader.read_u32().map(|v| v as u64),
        DW_EH_PE_udata8 => reader.read_u64().map(|v| v as u64),
        DW_EH_PE_sleb128 => reader.read_sleb128().map(|v| v as u64),
        DW_EH_PE_sdata2 => reader.read_i16().map(|v| v as u64),
        DW_EH_PE_sdata4 => reader.read_i32().map(|v| v as u64),
        DW_EH_PE_sdata8 => reader.read_i64().map(|v| v as u64),
        _ => {
            error!(
                "read_encoded_pointer(): unsupported pointer encoding: {:#X}: {:?}",
                encoding.0,
                encoding.static_string()
            );
            Err(gimli::Error::UnknownPointerEncoding)
        }
    }
}

/// Get encoding size.
#[allow(non_upper_case_globals)]
fn encoding_size(encoding: DwEhPe, arch_pointer_width: ArchPointerWidth) -> u64 {
    match encoding {
        DW_EH_PE_udata2 => 2,
        DW_EH_PE_udata4 => 4,
        DW_EH_PE_udata8 => 8,
        DW_EH_PE_sdata2 => 2,
        DW_EH_PE_sdata4 => 4,
        DW_EH_PE_sdata8 => 8,
        DW_EH_PE_absptr => arch_pointer_width.into(),
        _ => 0,
    }
}
