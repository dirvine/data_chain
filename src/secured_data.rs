// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1 This, along with the
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
use itertools::Itertools;
use chunk_store::ChunkStore;
use std::sync::{Arc, Mutex};
use std::path::{Path, PathBuf};
use data::{Data, DataIdentifier};
use maidsafe_utilities::serialisation;
use sha3::hash;
use sodiumoxide::crypto::sign::{PublicKey, Signature};
use chain::{BlockIdentifier, DataChain, NodeBlock};

/// Post and Delete require signed actions
/// Put of ledger SD also requires `SignedAction`
#[allow(missing_docs)]
pub enum DataAction {
    Put(DataIdentifier),
    Post(DataIdentifier),
    Delete(DataIdentifier),
}

/// signed action
#[allow(missing_docs)]
pub struct SignedAction {
    sigs: Vec<Signature>,
    action: DataAction,
}

impl SignedAction {
    /// Create a new signedAction
    pub fn new(action: DataAction, sigs: Vec<Signature>) -> SignedAction {
        SignedAction {
            sigs: sigs,
            action: action,
        }
    }

    /// Getter
    pub fn action(&self) -> &DataAction {
        &self.action
    }
    /// Getter
    pub fn sigs(&self) -> &[Signature] {
        &self.sigs
    }
}

/// API for data based operations.
pub struct SecuredData {
    cs: ChunkStore<[u8; 32], Data>,
    dc: Arc<Mutex<DataChain>>,
}

impl SecuredData {
    /// Construct new data container
    pub fn create_in_path(path: PathBuf,
                          max_disk_space: u64,
                          group_size: usize)
                          -> Result<SecuredData, Error> {
        let cs = try!(ChunkStore::new(path.clone(), max_disk_space));
        let dc = Arc::new(Mutex::new(try!(DataChain::create_in_path(path, group_size))));
        Ok(SecuredData { cs: cs, dc: dc })
    }

    /// Open an existing container from path
    pub fn from_path(path: PathBuf,
                     max_disk_space: u64,
                     group_size: usize)
                     -> Result<SecuredData, Error> {
        let cs = try!(ChunkStore::from_path(path.clone(), max_disk_space));
        let dc = Arc::new(Mutex::new(try!(DataChain::from_path(path, group_size))));
        Ok(SecuredData { cs: cs, dc: dc })
    }

    /// remove all disk based data
    pub fn clear_disk(&self, path: &Path) -> Result<(), Error> {
        self.dc.lock().unwrap().unlock();
        Ok(try!(fs::remove_dir_all(&path)))
    }

    /// Access to DataChain
    pub fn chain(&self) -> Arc<Mutex<DataChain>> {
        self.dc.clone()
    }

    /// Add a NodeBlock from another node
    /// If block is not a link and is valid wil return BlockIdentifier plus a bool
    /// to represent whether we have the data when the block is valid
    pub fn add_node_block(&mut self, nb: NodeBlock) -> Option<(BlockIdentifier, bool)> {
        if let Some(ref ans) = self.dc.lock().unwrap().add_node_block(nb.clone()) {
            if ans.is_link() {
                return None;
            }
            return Some((ans.clone(), self.cs.has(ans.hash())));

        }
        None
    }

    /// Retrieve data we have on disk, that is also marked valid in the data chain.
    pub fn get(&self, data_id: &DataIdentifier) -> Result<Data, Error> {
        if let Some(block_id) = self.dc
            .lock()
            .unwrap()
            .find_name(data_id.name()) {
            if block_id.valid {
                return Ok(try!(self.cs.get(&block_id.identifier().hash())));
            } else {
                return Err(Error::Validation);
            }
        }
        Err(Error::NoFile)
    }
    /// Will not remove ledger items
    fn trim_previous_data(&mut self, hash: &[u8; 32]) {
        if let Ok(ref item) = self.cs.get(hash) {
            match *item {
                Data::Structured(ref sd) => {
                    if sd.ledger() {
                        let _ = self.cs.delete(hash);
                    }
                }
                Data::Immutable(ref _id) => {
                    let _ = self.cs.delete(hash);
                }
                _ => {}
            }
        }
    }
    /// Add received data, return Result false if we do not have the corresponding
    /// **valid** NodeBlock for this data. Will return a BlockIDentifier from us
    /// that we must use to create a NodeBlock to send to peers. We also **must**
    /// add this NodeBlock ourselves to this container. This is done in this manner to
    /// prevent coupling with keypairs etc.
    ///
    /// **Versioned ledger structured data will be Put and paid for**
    pub fn put_data(&mut self, data: &Data) -> Result<BlockIdentifier, Error> {
        let hash = hash(&try!(serialisation::serialise(&data)));
        let id = match *data {
            Data::Immutable(ref im) if *im.name() == hash => BlockIdentifier::ImmutableData(hash),
            Data::Structured(ref sd) if sd.version() == 0 || sd.ledger() => {
                BlockIdentifier::StructuredData(hash, *sd.name(), sd.ledger())
            }
            _ => return Err(Error::BadIdentifier),
        };
        self.trim_previous_data(&hash);
        try!(self.cs.put(&hash, data));
        Ok(id)
    }

    /// Handle POST data
    /// This is a call that will only handle structured data
    ///
    /// **Will not accept versioned ledger based structuredData !**
    pub fn post_data(&mut self,
                     data: &Data,
                     _sig_act: &SignedAction)
                     -> Result<BlockIdentifier, Error> {
        let hash = hash(&try!(serialisation::serialise(&data)));
        let id = match *data {
            Data::Structured(ref sd) if !sd.ledger() => {
                BlockIdentifier::StructuredData(hash, *sd.name(), false)
            }
            _ => return Err(Error::BadIdentifier),
        };
        // Remove last element unless marked with ledger
        // TODO handle ledger bit
        if let Some(ref block_id) = self.dc
            .lock()
            .unwrap()
            .find_name(data.name()) {
            if !block_id.identifier().is_ledger() {
                let _ = self.cs.delete(block_id.identifier().hash());
                self.dc.lock().unwrap().remove(block_id.identifier());
            }
        }
        self.trim_previous_data(&hash);
        try!(self.cs.put(&hash, data));

        Ok(id)
    }

    /// Handle Delete data Unless ledger bit is set
    pub fn delete_data(&mut self,
                       data_id: &DataIdentifier,
                       _sig_act: &SignedAction)
                       -> Result<BlockIdentifier, Error> {
        if let Some(ref block_id) = self.dc
            .lock()
            .unwrap()
            .find_name(data_id.name()) {
            if !block_id.identifier().is_ledger() {
                let _ = self.cs.delete(block_id.identifier().hash());
                self.dc.lock().unwrap().remove(block_id.identifier());
                return Ok(block_id.identifier().clone());
            }
        }
        Err(Error::NoFile)
    }

    /// Return a chain for which we hold **all** of the data.
    /// Restricted to data that has a corresponding valid `Block`.
    pub fn provable_chain(&self, group_size: usize) -> DataChain {
        let keys = self.cs.keys();
        DataChain::from_blocks(self.dc
                                   .lock()
                                   .unwrap()
                                   .chain()
                                   .iter()
                                   .cloned()
                                   .filter(|x| x.valid)
                                   .filter(|x| {
                                       x.identifier().is_link() ||
                                       keys.contains(x.identifier().hash())
                                   })
                                   .collect_vec(),
                               group_size)
    }

    /// Remove any data on disk that we do not have a valid Block for
    pub fn purge_disk(&mut self) -> Result<(), Error> {
        let cs_keys = self.cs.keys();
        for dc_key in self.dc
            .lock()
            .unwrap()
            .chain()
            .iter()
            .cloned()
            .filter(|x| !x.identifier().is_link() && x.valid)
            .filter(|x| cs_keys.contains(x.identifier().hash())) {
            // only throws error on IO error not missing data
            // TODO test this !!
            try!(self.cs.delete(dc_key.identifier().hash()));
        }
        Ok(())
    }

    /// Confirm and merge a DataChain transmitted to us.
    /// This will trim (purge invalid) exsiting entries then merge valid entries.
    /// May be used to create a new chain from given chains on node startup.
    pub fn merge_chain(&mut self, chain: &mut DataChain) {
        self.dc.lock().unwrap().merge_chain(chain);
    }

    /// How many network events a given proover has been involved in (proover == node)
    /// First missed event stops the count
    // TODO this is very basic and requires some further discussion
    pub fn trust_level(&self, node: &PublicKey) -> usize {
        self.dc
            .lock()
            .unwrap()
            .chain()
            .iter()
            .rev()
            .take_while(|x| x.proof().iter().any(|z| z.key() == node))
            .count()
    }
    /// Find any data we should have, given our current chain
    pub fn required_data(&self) -> Vec<BlockIdentifier> {
        let keys = self.cs.keys();
        self.dc
            .lock()
            .unwrap()
            .chain()
            .iter()
            .filter(|x| !x.identifier().is_link() && x.valid)
            .filter(|x| !keys.contains(x.identifier().hash()))
            .map(|x| x.identifier().clone())
            .collect_vec()
    }

    /// Max space avilable for disk storage (as set by user)
    pub fn max_space(&self) -> u64 {
        self.cs.max_space()
    }

    /// Disk used so far.
    pub fn used_space(&self) -> u64 {
        self.cs.used_space()
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

        let store = unwrap!(SecuredData::create_in_path(storedir.clone(), 64, 999));
        assert!(&storedir.clone().exists());
        // Should fail to create existing dir
        assert!(SecuredData::create_in_path(storedir.clone(), 64, 999).is_err());
        assert!(storedir.exists());
        assert!(store.clear_disk(&storedir).is_ok());
        assert!(!storedir.exists());
    }

}
