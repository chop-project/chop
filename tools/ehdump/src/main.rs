use ehdump::dump_file;
use object::Object;
use std::{env, fs};

fn main() {
    for path in env::args().skip(1) {
        let file = fs::File::open(&path).unwrap();
        let mmap = unsafe { memmap::Mmap::map(&file).unwrap() };
        let object = object::File::parse(&*mmap).unwrap();
        let endian = if object.is_little_endian() {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };

        // Initialize a struct to store FDEs
        match dump_file(&object, endian) {
            Ok(x) => println!("{}", serde_json::to_string_pretty(&x).unwrap()),
            Err(err) => {
                println!("{}", err);
                return;
            }
        };
        println!("Finished OK!");
    }
}
