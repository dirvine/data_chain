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


// use sodiumoxide::crypto;
use maidsafe_utilities::serialisation;
// use block_identifier::BlockIdentifier;
// use node_block::{NodeBlock, NodeBlockProof};
use error::Error;

use std::io::{self, Read};
use std::fs;
use fs2::*;
use std::path::Path;

pub struct


    /// Create a new chain backed up on disk
	/// Provide the directory to create the files in
	pub fn new(path: &Path) -> io::Result<DataChain> {
		let path = path.join("data_chain");
        let file = try!(fs::OpenOptions::new().read(true).write(true).create_new(true).open(&path));
		// hold a lock on the file for the whole session
		try!(file.lock_exclusive());
        Ok(DataChain {
			chain : Blocks::default(),
			path : path.to_str().unwrap().to_string(),
			})
	}
 /// Open from existing directory
	pub fn open_path(path: &Path) -> Result<DataChain, Error> {
		let path = path.join("data_chain");
        let mut file = try!(fs::OpenOptions::new().read(true).write(true).create(false).open(&path));
		// hold a lock on the file for the whole session
		try!(file.lock_exclusive());
		let mut buf = Vec::<u8>::new();
		let _ = try!(file.read_to_end(&mut buf));
        Ok(DataChain {
			chain : try!(serialisation::deserialise::<Blocks>(&buf[..])),
			path : path.to_str().unwrap().to_string()
		})
	}

