// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0 This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use std::fs;
use error::Error;
use std::sync::{Arc, Mutex};
use chunk_store::ChunkStore;
use std::path::{Path, PathBuf};
use data::{Data, DataIdentifier};
use chain::{BlockIdentifier, DataChain, NodeBlock};


/// API for data based operations.
#[allow(unused)]
pub struct SecuredData<'a> {
    cs: ChunkStore<[u8; 32], Data>,
    dc: Arc<Mutex<DataChain<'a>>>,
}

impl<'a> SecuredData<'a> {
    /// Construct new data container
    pub fn create_in_path(path: &PathBuf, max_disk_space: u64) -> Result<SecuredData, Error> {
        let cs = try!(ChunkStore::new(path.clone(), max_disk_space));
        let dc = Arc::new(Mutex::new(try!(DataChain::create_in_path(path))));
        Ok(SecuredData { cs: cs, dc: dc })
    }

    /// Open an existing container from path
    pub fn from_path(_path: &Path) -> Result<SecuredData, Error> {
        unimplemented!();
    }

    /// remove all disk based data
    pub fn clear_disk(&self, path: &Path) -> Result<(), Error> {
        self.cs.unlock();
        self.dc.lock().unwrap().unlock();
        Ok(try!(fs::remove_dir_all(&path)))
    }

    /// Access to DataChain
    pub fn chain(&self) -> Arc<Mutex<DataChain<'a>>> {
        self.dc.clone()
    }

    /// Add a NodeBlock from another node
    /// If block is not a link and is valid wil return BlockIdentifier plus a bool
    /// to represent whether we have the data when the block is valid
    pub fn add_node_block(&mut self, nb: NodeBlock) -> Option<(BlockIdentifier, bool)> {
        if let Some(ref ans) = self.dc.lock().unwrap().add_node_block(nb.clone()) {
            return Some((ans.clone(), self.cs.has(&ans.hash().0)));
        }
        None
    }

    /// Retrieve data we have on disk, that is also marked valid in the data chain.
    pub fn get(&self, _data_id: &DataIdentifier) {
        unimplemented!();
    }
    /// Add received data, return Result false if we do not have the corresponding
    /// NodeBlock for this data (regardless of the block currently being valid)
    pub fn put_data(&mut self, _data: &Data) -> Result<(), Error> {
        unimplemented!();
    }

    /// Handle POST data
    /// This is a call that will only handle structured data
    pub fn post_data(&mut self, _data: &Data) -> Result<(), Error> {
        unimplemented!();
    }

    /// Handle Delete data
    pub fn delete_data(&mut self, _data_id: &DataIdentifier) -> Result<(), Error> {
        unimplemented!();
    }

    /// Return a chain for which we hold ALL of the data for and where each block is valid
    pub fn provable_chain(&self) -> DataChain {
        unimplemented!();
    }

    /// Remove any data on disk that we do not have a valid Block for
    pub fn purge_disk(&mut self) -> Result<(), Error> {
        unimplemented!();
    }

    /// Confirm and merge a DataChain transmitted to us.
    /// This will trim (purge invalid) exsiting entries then merge valid entries.
    /// May be used to create a new chain from given chains on node startup.
    pub fn merge_chain(&mut self, _chain: &DataChain) {
        unimplemented!();
    }

    /// Find any data we should have, given our current chain
    pub fn required_data(&self) -> Vec<DataIdentifier> {
        unimplemented!();
    }
    // ############ Dubious, should perhaps be private ###########
    /// Trim chain to previous common leading bits (previous vertice in binary tree)
    /// If our leading bits in group are 10111 then it will trim any 10110 data & links.
    pub fn trim_all_blocks_and_data(&mut self) {
        unimplemented!();
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tempdir::TempDir;

    #[test]
    fn disk_create_cleanup() {
        let tempdir = unwrap!(TempDir::new("test"));
        let storedir = tempdir.path().join("test");

        let store = unwrap!(SecuredData::create_in_path(&storedir, 64));
        assert!(storedir.exists());
        // Should fail to create existing dir
        assert!(SecuredData::create_in_path(&storedir.clone(), 64).is_err());
        assert!(storedir.exists());
        assert!(store.clear_disk(&storedir).is_ok());
        assert!(!storedir.exists());
    }
}
