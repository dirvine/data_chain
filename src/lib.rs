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
//! A chain will look like
//!
//! `link:data:data:data:data:link:link:data:data`
//! The link is a group agreement chain component which is created by sorting the closest nodes
//! to a network node (Address) and sending this hash, signed to that node.
//! The recipient will then receive these, `NodeBlocks` and create the chain link.
//! This link will allow the agreed members of the group so sign `DataBlocks` for the chain
//! If a majority of the link members sign the data, it is validly in the chain.
//! On group membership changes, a new link is constructed in the chain and the process repeats.
//! A chain can split and nodes will maintain several chains, dependent on data overlaps with
//! the chains links.
//! The link identifier is the hash of all group members that contains the current node.
//!
//! Containers of Chain Links only may also be maintained in groups to prove historic memberships
//! of a network. It is not well enough understoof the validity of this action, but it may prove
//! valuable in the event of network restarts.

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

use sodiumoxide::crypto;
// use sodiumoxide::crypto::hash;
use sodiumoxide::crypto::hash::sha256::Digest;
use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::sign::{Signature, PublicKey, SecretKey};
use maidsafe_utilities::serialisation;
use rayon::prelude::*;

const GROUP_SIZE: usize = 8;

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
    NoLink,
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
pub enum BlockIdentifier {
    Type1(u64),
    Type2(u64),
    /// This digest represents **this nodes** current close group
    /// This is unique to this node, but known by all nodes connected to it
    /// in this group.
    Link(Digest), // hash of group (all current close group id's)
}

impl BlockIdentifier {
    /// Define a name getter as data identifiers may contain more info that does
    /// not change the name (such as with structured data and versions etc.)
    /// In this module we do not care about other info and any validation is outwith this area
    /// Therefore we will delete before insert etc. based on name alone of the data element
    pub fn name(&self) -> Option<u64> {
        match *self {
            BlockIdentifier::Type1(name) => Some(name),
            BlockIdentifier::Type2(name) => Some(name),
            BlockIdentifier::Link(_) => None, // links do not have names
        }
    }

    /// Create a new chain link
    /// All group members should do this on each churn event
    /// All group members should also agree on the exact same members
    /// In a kademlia network then the kademlia invariant should enforce this group agreement.
    pub fn new_link(&mut self, group_ids: &mut [PublicKey]) -> Result<BlockIdentifier, Error> {
        let sorted = group_ids.sort();
        let serialised = try!(serialisation::serialise(&sorted));
        Ok(BlockIdentifier::Link(sha256::hash(&serialised)))
    }
}

/// If data block then this is sent by any group member when data is `Put`, `Post` or `Delete`.
/// If this is a link then it is sent with a `churn` event.
/// A `Link` is a nodeblock that each member must send each other in times of churn.
/// These will not accumulate but be `ManagedNode`  to `ManagedNode` messages in the routing layer
#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug, Clone)]
pub struct NodeBlock {
    identifier: BlockIdentifier,
    proof: (PublicKey, Signature),
}

impl NodeBlock {
    /// Create a Block (used by nodes in network to send to holders of `DataChains`)
    pub fn new(pub_key: &PublicKey,
               secret_key: &SecretKey,
               data_identifier: BlockIdentifier)
               -> Result<NodeBlock, Error> {
        let signature =
            crypto::sign::sign_detached(&try!(serialisation::serialise(&data_identifier))[..],
                                        secret_key);

        Ok(NodeBlock {
            identifier: data_identifier,
            proof: (pub_key.clone(), signature),
        })

    }
}

/// Every block has an attached proof type (group of signatures)
/// Link proofs also contain the public keys allowed to sign data blocks.
/// The link is ordered
/// Block signatures are placed in the appropriate slot of the array
#[allow(missing_docs)]
#[derive(RustcEncodable, RustcDecodable, PartialEq, Clone)]
pub enum Proof {
    Link(Vec<(PublicKey, Option<Signature>)>),
    Block([Option<Signature>; GROUP_SIZE]),
}

impl Proof {
    /// link proof
    pub fn link_proof(&self) -> Option<&Vec<(PublicKey, Option<Signature>)>> {
        match *self {
            Proof::Link(ref proof) => Some(&proof),
            _ => None,
        }
    }

    /// link proof
    pub fn block_proof(&self) -> Option<&[Option<Signature>; GROUP_SIZE]> {
        match *self {
            Proof::Block(ref proof) => Some(&proof),
            _ => None,
        }
    }
}

/// Used to validate chain
/// Block can be a data item or
/// a chain link.
#[derive(RustcEncodable, RustcDecodable, PartialEq, Clone)]
pub struct Block {
    identifier: BlockIdentifier,
    proof: Proof,
}

impl Block {
    /// construct a block
    pub fn new_block(data_id: BlockIdentifier) -> Block {
        Block {
            identifier: data_id,
            proof: Proof::Block([None; GROUP_SIZE]),
        }

    }
    /// construct a link (requires group members signing keys are known)
    pub fn new_link(data_id: BlockIdentifier, group_keys: &mut Vec<PublicKey>) -> Block {
        group_keys.sort();
        // FIXME
        let sorted_proof = group_keys.iter()
            .map(|x| (x.clone(), None))
            .collect();

        Block {
            identifier: data_id,
            proof: Proof::Link(sorted_proof),
        }

    }

    /// is this a link
    pub fn is_link(&self) -> bool {
        match self.proof {
            Proof::Link(_) => true,
            Proof::Block(_) => false,
        }
    }

    /// access proof
    pub fn proof(&self) -> &Proof {
        &self.proof
    }

    /// name of block is name of identifier
    pub fn name(&self) -> Option<u64> {
        self.identifier.name()
    }

    /// Get the identifier
    pub fn identifier(&self) -> &BlockIdentifier {
        &self.identifier
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
    chain: Vec<Block>,
}

impl DataChain {
    /// Create a new chain with no elements yet.
    pub fn new() -> DataChain {
        DataChain { chain: Vec::new() }
    }
    /// Nodes always validate a chain before accepting it
    pub fn validate(&mut self) -> Result<(), Error> {
        if self.chain.is_empty() {
            return Ok(());
        }
        // Ok(try!(self.validate_majorities().and(self.validate_signatures())))
        // validate links
        // validate blocks
        // prune blocks that will never complete (no remaining consensus available)
        Ok(())
    }


    /// Add a Block to the chain
    pub fn add_block(&mut self, data_block: Block) {
        self.chain.push(data_block);
    }

    /// number of non-deleted blocks
    pub fn len(&self) -> usize {
        self.chain.len()
    }

    /// Contains no blocks that are not deleted
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    /// Delete a block (will not delete a link)
    pub fn delete(&mut self, data_id: BlockIdentifier) {
        match data_id {
            BlockIdentifier::Link(_) => {}
            _ => self.chain.retain(|x| *x.identifier() != data_id),
        }
    }

    /// Delete a block referred to by name
    /// Will either remove a block as long as consensus would remain intact
    /// Otherwise mark as deleted.
    /// If block is in front of container (`.fisrt()`) then we delete that.
    pub fn delete_name(&mut self, name: u64) {

        self.chain.retain(|x| if let Some(y) = x.name() {
            y != name
        } else {
            false
        });
    }

    /// Should equal the current common_close_group
    pub fn get_last_link(&self) -> Option<&Block> {
        self.chain.iter().rev().find((|&x| x.is_link()))
    }

    fn get_recent_link(&self, block: &Block) -> Option<&Block> {
        self.chain
            .iter()
            .rev()
            .skip_while(|x| x.identifier() != block.identifier())
            .find((|&x| x.is_link()))
    }

    #[allow(unused)]
    fn validate_links(&self) -> Result<(), Error> {

        // if Some(item) = self.chain.iter().find(|&x| x.is_link()) {
        // 	let data = try!(serialisation::serialise(&item.identifier));
        // 	if item.proof.iter().filter(|x| x.1.is_some() &&
        //           crypto::sign::verify_detached(x.1, &data[..], x.0) ).count() * 2 > GROUP_SIZE {
        //
        // 	}
        // }

        if self.chain
            .iter()
            .zip(self.chain.iter().skip(1))
            .all(|block| self.has_majority(block.0, block.1)) {
            Ok(())
        } else {
            Err(Error::Majority)
        }
    }

    /// Validate an individual block. Will get latest link and confirm all signatures
    /// were from last known group. Majority of sigs is confirmed.
    pub fn validate_block(&self, block: &Block) -> Result<(), Error> {
        if let Some(ref link) = self.get_recent_link(block) {
            try!(self.validate_block_with_proof(block, &link.proof))
        }
        return Err(Error::NoLink);
    }

    fn validate_block_with_proof(&self, block: &Block, proof: &Proof) -> Result<(), Error> {
        let id = try!(serialisation::serialise(block.identifier()));
        if let Some(link_proof) = proof.link_proof() {
            let mut good = 0;
            for (count, &(key, _)) in link_proof.iter().enumerate() {
                if let Some(ref item) = block.proof()
                    .block_proof()
                    .and_then(|x| x.iter().nth(count))
                    .and_then(|&x| x) {
                    if crypto::sign::verify_detached(item, &id[..], &key) {
                        good += 1;
                    }
                }
            }
            if good * 2 > GROUP_SIZE {
                return Ok(());
            }
        }
        return Err(Error::Majority);
    }

    #[allow(unused)]
    fn validate_signatures(&self) -> Result<(), Error> {
        Ok(())
        // if self.chain
        //     .iter()
        //     .all(|x| {
        //         if let Ok(data) = serialisation::serialise(&x.identifier) {
        //             x.proof
        //                 .iter()
        //                 .all(|v| crypto::sign::verify_detached(v.1, &data[..], v.0))
        //         } else {
        //             false
        //         }
        //     }) {
        //     Ok(())
        // } else {
        //     Err(Error::Signature)
        // }
    }

    #[allow(unused)]
    fn has_majority(&self, _block0: &Block, _block1: &Block) -> bool {
        // block1.proof.keys().filter(|k| block0.proof.contains_key(k)).count() as u64 * 2 >
        // self.group_size
        false
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
        let test_data1 = BlockIdentifier::Type1(1u64);
        let test_data2 = BlockIdentifier::Type1(1u64);
        let test_data3 = BlockIdentifier::Type2(1u64);
        let test_node_data_block1 = NodeBlock::new(&keys.0, &keys.1, test_data1).expect("fail1");
        let test_node_data_block2 = NodeBlock::new(&keys.0, &keys.1, test_data2).expect("fail2");
        let test_node_data_block3 = NodeBlock::new(&keys.0, &keys.1, test_data3).expect("fail3");
        assert_eq!(test_node_data_block1.clone(), test_node_data_block2.clone());
        assert!(test_node_data_block1 != test_node_data_block3.clone());
        assert!(test_node_data_block2 != test_node_data_block3);

    }

    fn create_data_chain(count: u64) -> DataChain {
        let group_size = 8;
        let mut chain = DataChain::new(group_size);

        let keys = (0..count + group_size)
            .map(|_| crypto::sign::gen_keypair())
            .collect_vec();




        let data_blocks = (0..count)
            .map(|x| {
                let mut block = if x % 2 == 0 {
                    Block::new(BlockIdentifier::Type1(x))
                } else {
                    Block::new(BlockIdentifier::Type2(x))
                };
                let data = serialisation::serialise(&block.identifier).expect("serialise fail");
                for y in 0..group_size {
                    let _ = block.add_node(keys[x as usize + y as usize].0,
                                           crypto::sign::sign_detached(&data[..],
                                                                       &keys[x as usize +
                                                                             y as usize]
                                                                           .1));
                }
                block
            })
            .collect_vec();

        let now = time::Instant::now();

        for i in data_blocks.iter() {
            chain.add_block(i.clone()).expect("chain fill failed");
        }
        println!("Took {:?}.{:?} seconds to add {:?} blocks",
                 now.elapsed().as_secs(),
                 now.elapsed().subsec_nanos(),
                 chain.len());
        chain
    }

    #[test]
    fn create_and_validate_chain() {
        let count = 1000;
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
        let count = 100i64;
        let mut chain = create_data_chain(count as u64);

        assert_eq!(chain.len(), count as usize);
        assert_eq!(chain.chain.iter().map(|x| !x.deleted).count(),
                   count as usize);

        for i in 0..count {
            let _ = chain.delete(i as u64);
        }

        // internally all entries there, but marked deleted (entry 0 removed)
        assert_eq!(chain.chain.iter().map(|x| x.deleted).count(), 0);
        assert_eq!(chain.len(), 0);
        assert!(chain.empty());
    }

    #[test]
    fn delete_rev_and_validate() {
        let count = 100i64;
        let mut chain = create_data_chain(count as u64);

        assert_eq!(chain.len(), count as usize);
        assert_eq!(chain.chain.iter().map(|x| !x.deleted).count(),
                   count as usize);

        for i in count..0 {
            let _ = chain.delete(i as u64);
        }
        let _ = chain.delete(0);
        // internally all entries there, but marked deleted (entry 0 removed)
        assert_eq!(chain.chain.iter().map(|x| x.deleted).count() + 1,
                   count as usize);
        assert_eq!(chain.len() + 1, count as usize);
        assert!(!chain.empty());
        let _ = chain.validate().expect("validate failed");

    }



}
