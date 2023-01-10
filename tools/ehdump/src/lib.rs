use gimli::{BaseAddresses, CieOrFde, EhFrame, UnwindSection};
use object::{Object, ObjectSection};
use std::{fs, str, path::Path};
mod db;
mod lsda;
use anyhow::bail;
use anyhow::{anyhow, Error};
use fallible_iterator::FallibleIterator;
use serde::{Deserialize, Serialize};
use std::ffi::CStr;
use std::fs::File;
use std::os::raw::c_char;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchPointerWidth {
    Width64Bit,
    Width32Bit,
}

impl std::convert::From<ArchPointerWidth> for u64 {
    fn from(width: ArchPointerWidth) -> Self {
        match width {
            ArchPointerWidth::Width32Bit => 4,
            ArchPointerWidth::Width64Bit => 8,
        }
    }
}

impl std::convert::From<&ArchPointerWidth> for u64 {
    fn from(width: &ArchPointerWidth) -> Self {
        match width {
            ArchPointerWidth::Width32Bit => 4,
            ArchPointerWidth::Width64Bit => 8,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct Action {
    ar_filter: i64,
    ar_disp: i64,
    // 0x0 for catch_all , address of type_info in case of some particular exception
    // (positive ar_filter), the "missing" string in case the LSDA does not contain
    // a type table, the "encoding" string if we've encountered an unhandled type
    // table encoding and a list of type_info pointers for negative ar_filters.
    ar_info: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct CS {
    start: String,
    end: String,
    lp: String,
    actions: Vec<Action>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LSDA {
    lsda_ptr: String,
    cses: Vec<CS>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FDE {
    fstart: String,
    fend: String,
    lsda: LSDA,
}

/* @binpath - path to binary for which we parse the exception info structs.

    Writes an FDEs structure as a JSON string to file @binpath.json.
*/
#[no_mangle]
pub extern "C" fn write_exception_info_json(binpath: *const c_char) {
    let binpath_cstr = unsafe {
        assert!(!binpath.is_null());

        CStr::from_ptr(binpath)
    };
    let path = binpath_cstr.to_str().unwrap();
    let file = fs::File::open(&path).unwrap();
    let mmap = unsafe { memmap::Mmap::map(&file).unwrap() };
    let object = object::File::parse(&*mmap).unwrap();
    let endian = if object.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };

    let fdes_obj = dump_file(&object, endian).unwrap();
    let terminator: &str = ".json";
    let fname : &str = Path::new(path).file_name().unwrap().to_str().unwrap();
    let temp_file = format!("/tmp/{}{}", fname, terminator);
    serde_json::to_writer(&File::create(&temp_file).unwrap(), &fdes_obj).unwrap();
}

#[no_mangle]
pub extern "C" fn write_exception_info_db(id: i32, exception_type: i32) -> Result<(), Error> {
    let mut client = db::DB::new()?;

    let file_sha = client.get_file_sha256(id)?;

    let path = format!("./extracted/{}", file_sha);

    let file = fs::File::open(&path).unwrap();
    let mmap = unsafe { memmap::Mmap::map(&file).unwrap() };
    let object = object::File::parse(&*mmap).unwrap();
    let endian = if object.is_little_endian() {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };

    let fdes = dump_file(&object, endian).map_err(|err| {
        println!("{}", err);
        client.write_null_analysis_data(id, exception_type);
        err
    })?;

    let json_value = serde_json::to_value::<&Vec<FDE>>(&fdes).unwrap();

    client.write_analysis_data(id, exception_type, &json_value)?;

    Ok(())
}

fn dump_fde<R, Offset>(
    object: &object::File,
    fde: gimli::FrameDescriptionEntry<R, Offset>,
) -> Result<FDE, Error>
where
    R: gimli::read::Reader<Offset = Offset>,
    Offset: gimli::read::ReaderOffset,
{
    let lsda_ptr = match fde.lsda() {
        Some(gimli::Pointer::Direct(lsda_ptr)) => lsda_ptr,
        Some(x) => bail!("other: {:?}", x),
        None => bail!("No LSDA pointer!"),
    };

    let some_lsda = LSDA {
        lsda_ptr: format!("0x{:x}", lsda_ptr),
        cses: Vec::new(),
    };

    let mut some_fde = FDE {
        fstart: format!("0x{:x}", fde.initial_address()),
        fend: format!("0x{:x}", fde.initial_address() + fde.len()),
        lsda: some_lsda,
    };

    let section = object
        .sections()
        .filter(|section| {
            section.address() <= lsda_ptr && lsda_ptr < section.address() + section.size()
        })
        .next()
        .ok_or(anyhow!("could not get section for lsda pointer"))?;

    let lsda_data = section
        .data_range(lsda_ptr, section.size() + section.address() - lsda_ptr)?
        .ok_or(anyhow!("Could not get lsda slice"))?;

    let pointer_width: ArchPointerWidth = match object.is_64() {
        true => ArchPointerWidth::Width64Bit,
        false => ArchPointerWidth::Width32Bit,
    };

    let table = lsda::GccExceptTableArea::new(
        lsda_data,
        gimli::NativeEndian,
        fde.initial_address(),
        pointer_width,
    );

    let mut cses = table.call_site_table_entries()?;

    let mut ttable = table.type_table()?;

    while let Some(cse) = cses.next()? {
        let mut some_cs = CS {
            start: format!("0x{:x}", cse.range_of_covered_addresses().start),
            end: format!("0x{:x}", cse.range_of_covered_addresses().end),
            lp: cse
                .landing_pad_address()
                .map(|addr| format!("0x{:x}", addr))
                .unwrap_or("0x0".to_string()),
            actions: Vec::new(),
        };

        let action_vec = match cse
            .action_offset()
            .and_then(|offset| table.action_records_for_offset(offset).ok())
            .and_then(|it| it.collect::<Vec<_>>().ok())
        {
            Some(x) => x,
            None => Vec::new(),
        };

        for action in action_vec.into_iter() {
            let some_action = Action {
                ar_filter: action.ar_filter,
                ar_disp: action.ar_disp,
                ar_info: match ttable.get_type(action, lsda_ptr) {
                    Ok(x) if x.len() == 0 => "cleanup".to_string(),
                    Ok(x) => {
                        let mut result_str = x
                            .into_iter()
                            .map(|i| format!("0x{:x} ", i))
                            .collect::<String>();
                        result_str.pop();
                        result_str
                    }
                    Err(gimli::Error::UnknownPointerEncoding) => "encoding".to_string(),
                    Err(_) => "missing".to_string(),
                },
            };
            some_cs.actions.push(some_action);
        }
        some_fde.lsda.cses.push(some_cs);
    }

    return Ok(some_fde);
}

pub fn dump_file(object: &object::File, endian: gimli::RunTimeEndian) -> Result<Vec<FDE>, Error> {
    let mut fdes: Vec<FDE> = Vec::new();

    // exit we're missing .eh_frame_hdr, .eh_frame or .text section
    if object.section_by_name(".eh_frame").is_none() || object.section_by_name(".text").is_none() {
        return Err(anyhow!("Error sections .eh_frame or .text are missing."));
    }

    let mut bases = BaseAddresses::default()
        .set_text(object.section_by_name(".text").unwrap().address())
        .set_eh_frame(object.section_by_name(".eh_frame").unwrap().address());

    if !object.section_by_name(".eh_frame_hdr").is_none() {
        bases = bases.set_eh_frame_hdr(object.section_by_name(".eh_frame_hdr").unwrap().address())
    }
    if !object.section_by_name(".got").is_none() {
        bases = bases.set_got(object.section_by_name(".got").unwrap().address());
    };

    let eh_frame = EhFrame::new(
        object
            .section_by_name(".eh_frame")
            .expect("no_eh_frame")
            .data()
            .expect("could not get data"),
        endian,
    );

    let mut ehf_entry = eh_frame.entries(&bases);
    while let Some(entry) = ehf_entry.next()? {
        match entry {
            CieOrFde::Cie(_) => {}
            CieOrFde::Fde(partial) => {
                let fde = partial.parse(EhFrame::cie_from_offset)?;
                if let Some(fde) = dump_fde(object, fde).ok() {
                    fdes.push(fde);
                }
            }
        };
    }
    Ok(fdes)
}
