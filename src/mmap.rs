// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net
// Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3,
// depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project
// generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.
// This, along with the
// Licenses can be found in the root directory of this project at LICENSE,
// COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network
// Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
// OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions
// and limitations
// relating to use of the SAFE Network Software.

// use std::io::{Write, Read};
use std::io;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;
// use std::{fs, iter};
use std::fs;
use memmap::{Mmap, Protection};

/// A memory map backed data chain
#[allow(unused)]
pub struct FileDataChain {
    map: Arc<Mmap>,
    offset: usize,
    len: usize,
}



impl FileDataChain {
    /// Open or create a FIleDataChain
    pub fn create(&self, path: String, len: u64) -> io::Result<FileDataChain> {
        let file = try!(fs::OpenOptions::new()
            .write(true)
            .create(true)
             .open(&path));
            try!(file.set_len(len));
        Ok(try!(Self::open(&file)))
    }

    /// Open an existing DataChain for read/write mode
    pub fn open(path: &fs::File) -> io::Result<FileDataChain> {
        Ok(try!(Mmap::open(path, Protection::ReadWrite)).into())

    }

    /// Open a new memory map from the path given.
    pub fn open_path<P: AsRef<Path>>(path: P) -> io::Result<FileDataChain> {
        FileDataChain::open(&try!(fs::File::open(path)))
    }

    /// Returns the size in byte of the memory map.
    ///
    /// If it is a range, the size is the size of the range.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Slice this memory map to a new `offset` and `len`.
    ///
    /// # Panics
    ///
    /// If the new range is outside the bounds of the map
    pub fn range(&self, offset: usize, len: usize) -> FileDataChain {
        assert!(offset + len <= self.len);
        FileDataChain {
            map: self.map.clone(),
            offset: self.offset + offset,
            len: len,
        }
    }

    /// Write date to map
    /// # Safety
    /// This method currently unsafe (rust 0.9)
#[allow(unsafe_code)]
    pub unsafe fn write(&mut self, data: &[u8]) -> io::Result<usize> {
       match Arc::get_mut(&mut self.map) {
    	   	None =>  Ok(0),
       		 Some(ptr) => ptr.as_mut_slice().write(data)
		}
	}


}

impl Clone for FileDataChain {
    fn clone(&self) -> FileDataChain {
        FileDataChain {
            map: self.map.clone(),
            offset: self.offset,
            len: self.len,
        }
    }
}

impl From<Mmap> for FileDataChain {
    fn from(mmap: Mmap) -> FileDataChain {
        let len = mmap.len();
        FileDataChain {
            map: Arc::new(mmap),
            offset: 0,
            len: len,
        }
    }
}
