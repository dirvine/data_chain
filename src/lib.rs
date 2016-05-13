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

//! #data_blocks
//! Data blocks can be chained to provide verifiable assuredness that they contain network valid
//! data and not injected.
//!
//! This crate assumes these objects below are relevent to `close_groups` this allows integrity
//! check of the `DataChain` in so far as it will hold valid data identifiers agreed by this group
//! & all groups since the group/network started.
//!
//! These chains allow nodes to become `archive nodes` on a network and also ensure data integrity
//! AS LONG AS the data identifiers hold a validating element such as hash of the data itself.
//!
//! Another purpose of these chains is to allow network restarts with valid data. Obviously this
//! means the network nodes will have to tr and restart as the last known ID they had. Vaults
//! will require to accept or reject such nodes in normal operation. On network restart though
//! these nodes may be allowed to join a group if they can present a `DataChain` that appears
//! healthy, even if there is not yet enough consensus to `trust` the data iself just yet.
//! additional nodes will also join this group and hopefully confirm the data integrity is agreed
//! as the last `DataBlock` should contain a majorit of existing group members that have signed.
//!
//! Nodes do no require to become `Archive nodes` if they have limited bandwidth or disk space, but
//! they are still valuable as transient nodes which may deliver data stored whle they are in the
//! group. Such nodes may only be involved in consensus and routing stability messages, returning
//! a `Nack` to any `Get` request  due to upstream bandwidth limitations.
//!
//! Several enhancement can be made to this scheme with a much deper investigation into any
//! attack vectors. Such as
#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://dirvine.github.io/data_blocks")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]


#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippyclippy_pedantic))]
#![cfg_attr(feature="clippy", allow(use_debug))]

extern crate sodiumoxide;
extern crate rustc_serialize;
#[macro_use]
extern crate maidsafe_utilities;
#[cfg(test)]
extern crate itertools;
extern crate rayon;

use std::collections::HashMap;
use sodiumoxide::crypto;
use sodiumoxide::crypto::sign::{Signature, PublicKey, SecretKey};
use maidsafe_utilities::serialisation;
use rayon::prelude::*;

/// Error types.
///
/// Hopefully sodiumoxide eventually defines errors properly, otherwise this makes little sense.
#[allow(missing_docs)]
#[derive(Debug)]
pub enum Error {
    Serialisation(serialisation::SerialisationError),
    Crypto,
    Validation,
    Signature,
    Majority,
}

impl From<serialisation::SerialisationError> for Error {
    fn from(orig_error: serialisation::SerialisationError) -> Self {
        Error::Serialisation(orig_error)
    }
}

impl From<()> for Error {
    fn from(_: ()) -> Self {
        Error::Crypto
    }
}

/// Dummy data identifiers for this crate
#[allow(missing_docs)]
#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug, Clone)]
pub enum DataIdentifier {
    Type1(u64),
    Type2(u64),
}

impl DataIdentifier {
    /// Define a name getter as data identifiers may contain more info that does
    /// not change the name (such as with structured data and versions etc.)
    /// In this module we do not care about other info and any validation is outwith this area
    /// Therefore we will delete before insert etc. based on name alone of the data element
    pub fn name(&self) -> u64 {
        match *self {
            DataIdentifier::Type1(name) => name,
            DataIdentifier::Type2(name) => name,
        }
    }
}



/// Sent by any group member when data is `Put`, `Post` or `Delete` in this group
#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug, Clone)]
pub struct NodeDataBlock {
    identifier: DataIdentifier,
    proof: (PublicKey, Signature),
}

impl NodeDataBlock {
    /// Create a DataBlock (used by nodes in network to send to holders of `DataChains`)
    pub fn new(pub_key: &PublicKey,
               secret_key: &SecretKey,
               data_identifier: DataIdentifier)
               -> Result<NodeDataBlock, Error> {
        let signature =
            crypto::sign::sign_detached(&try!(serialisation::serialise(&data_identifier))[..],
                                        secret_key);

        Ok(NodeDataBlock {
            identifier: data_identifier,
            proof: (pub_key.clone(), signature),
        })

    }
}

/// Used to validate chain `linksi`.
/// On a network churn event the latest `DataBlock` is copied from the chain and sent
/// To new node. The `lost Nodes` signature is removed. The new node receives this - signs a
/// `NodeBlock  for this `DataIdentifier` and returns it to the `archive node`
#[derive(RustcEncodable, RustcDecodable, Clone)]
pub struct DataBlock {
    identifier: DataIdentifier,
    proof: HashMap<PublicKey, Signature>,
    deleted: bool, // we can mark as deleted if removing entry would invalidate the chain
}

impl DataBlock {
    /// Construct a DataBlock
    pub fn new(data_id: DataIdentifier) -> DataBlock {
        DataBlock {
            identifier: data_id,
            proof: HashMap::new(),
            deleted: false,
        }
    }
    /// Mark block as deleted
    pub fn mark_deleted(&mut self) {
        self.deleted = false;
    }

    /// Get the identifier
    pub fn identifier(&self) -> &DataIdentifier {
        &self.identifier
    }

    /// Add a NodeDataBlock (i.e. after accumulation there could be slow nodes)
    pub fn add_node(&mut self, public_key: PublicKey, signature: Signature) -> Result<(), Error> {

        let data = try!(serialisation::serialise(&self.identifier));
        if crypto::sign::verify_detached(&signature, &data[..], &public_key) {
            let _ = self.proof.insert(public_key, signature);
            Ok(())
        } else {
            return Err(Error::Signature);
        }
    }
}

/// Created by holder of chain, can be passed to others as proof of data held.
/// This object is verifiable if :
/// The last validation contains the majority of current close group
/// OR on network restart the nodes all must try and restart on
/// previous names. They can continue any validation of the holder of a chain.
/// This requires nodes to always restart as last ID and if there was no restart they are rejected
/// at vault level.
/// If there was a restart then the nodes should validate and continue.
/// N:B this means all nodes can use a named directory for data_store and clear if they restart
/// as a new id. This allows cleanup of old data_cache directories.
#[derive(RustcEncodable, RustcDecodable)]
pub struct DataChain {
    chain: Vec<DataBlock>,
    group_size: u64,
}

impl DataChain {
    /// Create a new chain with no elements yet.
    pub fn new(group_size: u64) -> DataChain {
        DataChain {
            chain: Vec::new(),
            group_size: group_size,
        }
    }
    /// Nodes always validate a chain before accepting it
    pub fn validate(&mut self) -> Result<(), Error> {
        Ok(try!(self.validate_majorities().and(self.validate_signatures())))
    }

    /// Size of close group (maximum proof size)
    pub fn group_size(&self) -> u64 {
        self.group_size
    }

    /// Add a DataBlock to the chain
    pub fn add_block(&mut self, data_block: DataBlock) -> Result<(), Error> {
        let data = try!(serialisation::serialise(&data_block.identifier));

        if let Some(last) = self.chain.last() {
            if !self.has_majority(last, &data_block) {
                return Err(Error::Majority);
            }
        }

        if !data_block.proof
                      .iter()
                      .all(|v| crypto::sign::verify_detached(v.1, &data[..], v.0)) {
            return Err(Error::Signature);
        }
        // TODO Remove any old copies of this data from the chain. It should not happen though
        self.chain.push(data_block);
        Ok(())
    }

    /// Delete a block
    /// Will either remove a block as long as consensus would remain intact
    /// Otherwise mark as deleted.
    /// If block is in front of container (`.fisrt()`) then we delete that.
    pub fn delete(&mut self, name: u64) -> Option<DataBlock> {
        if let Ok(item) = self.chain
                              .binary_search_by(|probe| probe.identifier().name().cmp(&name)) {
            if self.chain.len() == item ||
               self.has_majority(&self.chain[item], &self.chain[item + 1]) {
                // we can  maintain consensus by removing this iteem
                return Some(self.chain.remove(item));
            } else {
                // mark as deleted
                self.chain[item].mark_deleted();
                return Some(self.chain[item].clone());
            }
        }
        None
    }

    fn validate_majorities(&self) -> Result<(), Error> {
        if self.chain
               .iter()
               .zip(self.chain.iter().skip(1))
               .all(|block| self.has_majority(block.0, block.1)) {
            Ok(())
        } else {
            Err(Error::Majority)
        }
    }

    fn validate_signatures(&self) -> Result<(), Error> {
        if self.chain
               .iter()
               .all(|x| {
                   if let Ok(data) = serialisation::serialise(&x.identifier) {
                       x.proof
                        .iter()
                        .all(|v| crypto::sign::verify_detached(v.1, &data[..], v.0))
                   } else {
                       false
                   }
               }) {
            Ok(())
        } else {
            Err(Error::Signature)
        }
    }

    fn has_majority(&self, block0: &DataBlock, block1: &DataBlock) -> bool {
        block1.proof.keys().filter(|k| block0.proof.contains_key(k)).count() as u64 * 2 >
        self.group_size

    }
}



#[cfg(test)]

mod tests {
    use super::*;
    use sodiumoxide::crypto;
    use itertools::Itertools;
    use maidsafe_utilities::serialisation;
    use std::time;

    #[test]
    fn simple_node_data_block_comparisons() {
        let keys = crypto::sign::gen_keypair();
        let test_data1 = DataIdentifier::Type1(1u64);
        let test_data2 = DataIdentifier::Type1(1u64);
        let test_data3 = DataIdentifier::Type2(1u64);
        let test_node_data_block1 = NodeDataBlock::new(&keys.0, &keys.1, test_data1)
                                        .expect("fail1");
        let test_node_data_block2 = NodeDataBlock::new(&keys.0, &keys.1, test_data2)
                                        .expect("fail2");
        let test_node_data_block3 = NodeDataBlock::new(&keys.0, &keys.1, test_data3)
                                        .expect("fail3");
        assert_eq!(test_node_data_block1.clone(), test_node_data_block2.clone());
        assert!(test_node_data_block1 != test_node_data_block3.clone());
        assert!(test_node_data_block2 != test_node_data_block3);

    }

    fn create_data_chain(count: u64) -> DataChain {
        let group_size = 4;
        let mut chain = DataChain::new(group_size);

        let keys = (0..count + group_size)
                       .map(|_| crypto::sign::gen_keypair())
                       .collect_vec();




        let mut data_blocks = (0..count)
                                  .map(|x| {
                                      let mut block = if x % 2 == 0 {
                                          DataBlock::new(DataIdentifier::Type1(x))
                                      } else {
                                          DataBlock::new(DataIdentifier::Type2(x))
                                      };
                                      let data = serialisation::serialise(&block.identifier)
                                                     .expect("serialise fail");
                                      for y in 0..group_size {
                                          let _ = block.add_node(keys[x as usize + y as usize].0,
                                       crypto::sign::sign_detached(&data[..],
                                                                   &keys[x as usize + y as usize]
                                                                        .1));
                                      }
                                      block
                                  })
                                  .collect_vec();

        let now = time::Instant::now();

        let _ = data_blocks.drain(..)
                           .map(|x| chain.add_block(x).expect("chain fill failed"));
        println!("Took {:?}.{:?} seconds to add {:?} blocks",
                 now.elapsed().as_secs(),
                 now.elapsed().subsec_nanos(),
                 count);
        chain
    }

    #[test]
    fn create_and_validate_chain() {
        let count = 10000;
        let mut chain = create_data_chain(count);

        let now1 = time::Instant::now();
        let _ = chain.validate().expect("validate failed");
        println!("Took {:?}.{:?} seconds to validate  {:?} blocks",
                 now1.elapsed().as_secs(),
                 now1.elapsed().subsec_nanos(),
                 count);

    }


    #[test]
    fn delete_all_and_validate() {
        let count = 100;
        let mut chain = create_data_chain(count);
        for i in 0..count {
            let _ = chain.delete(i);
        }
        let _ = chain.validate().expect("validate failed");

    }


}
