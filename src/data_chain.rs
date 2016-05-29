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


use maidsafe_utilities::serialisation;
use itertools::Itertools;
use proof::Proof;
use block::Block;
use block_identifier::BlockIdentifier;
use node_block::{NodeBlock, NodeBlockProof};
use sodiumoxide::crypto;
use sodiumoxide::crypto::hash::sha256::Digest;
use error::Error;

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


    /// Each node in group will send a `NodeBlock` on each `churn` `put `post` or `delete` event
    pub fn add_node_block(&mut self, node_block: &mut NodeBlock) -> Result<(), Error> {
        if let Some(mut _entry) = self.chain.iter_mut().find(|x| x.identifier() == node_block.identifier()) {
              // self.add_to_identifier(entry, node_block.proof())
       unimplemented!()
        } else {
             // let block = Block::new_link
             //  self.chain.push()
       unimplemented!()
        }
    }
#[allow(unused)]
    fn add_to_identifier(&mut self, block: &mut Block, key_sig: &NodeBlockProof) -> Result<(), Error> {
        if block.is_link() {
            self.add_to_link(block, key_sig)
        } else {
            self.add_to_block(block, key_sig)
        }
    }

#[allow(unused)]
    fn add_to_block(&mut self, block: &mut Block, key_sig: &NodeBlockProof) -> Result<(), Error> {
       unimplemented!()

    }

#[allow(unused)]
    fn add_to_link(&mut self, block: &mut Block, key_sig: &NodeBlockProof) -> Result<(), Error> {
       unimplemented!()

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

    /// Delete a block referred to by hash
    pub fn delete_block(&mut self, hash: Digest) {
        self.chain.retain(|x| x.hash() != hash);
    }

    /// Should equal the current common_close_group
    pub fn get_last_link(&self) -> Option<&Block> {
        self.chain.iter().rev().find((|&x| x.is_link()))
    }

    /// Find block from top and get next link
    fn get_recent_link(&self, block: &Block) -> Option<&Block> {
        self.chain
            .iter()
            .rev()
            .skip_while(|x| x.identifier() != block.identifier())
            .find((|&x| x.is_link()))
    }

    /// Validate all links in chain
    pub fn validate_all_links(&self) -> bool {
        // TODO split into 2 iterators and not run filters on each like this

        self.chain
            .iter()
            .filter(|&x| self.validate_link_signatories(&x).is_ok())
            .filter_map(|x| x.proof().link_proof())
            .zip(self.chain
                .iter()
                .filter(|&x| self.validate_link_signatories(&x).is_ok())
                .filter_map(|x| {
                    x.proof()
                        .link_proof()
                })
                .skip(1))
            .all(|link| {
                link.0
                    .iter()
                    .filter_map(|x| x.1)
                    .collect_vec()
                    .iter()
                    .filter_map(|&x| link.1.iter().filter_map(|x| x.1).find(|&y| y == x))
                    .count() * 2 > ::GROUP_SIZE
            })
    }

    // Confirm a link contains majority members and they all signed digest
    fn validate_link_signatories(&self, link: &Block) -> Result<(), Error> {
        let id = try!(serialisation::serialise(link.identifier()));
        if let Some(link_proof) = link.proof().link_proof() {
            let mut good = 0;
            for &(key, sig) in link_proof.iter() {
                if let Some(signature) = sig {
                    if crypto::sign::verify_detached(&signature, &id[..], &key) {
                        good += 1;
                    }
                }
            }
            if good * 2 > ::GROUP_SIZE {
                return Ok(());
            }
        }
        return Err(Error::Majority);
    }

    /// Validate an individual block. Will get latest link and confirm all signatures
    /// were from last known group. Majority of sigs is confirmed.
    pub fn validate_block(&self, block: &Block) -> Result<(), Error> {
        if let Some(ref link) = self.get_recent_link(block) {
            try!(self.validate_block_with_proof(block, &link.proof()))
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
            if good * 2 > ::GROUP_SIZE {
                return Ok(());
            }
        }
        return Err(Error::Majority);
    }
}


// #[cfg(test)]
//
// mod tests {
//     use super::*;
//     use sodiumoxide::crypto;
//     use maidsafe_utilities::serialisation;
//     // use std::time;
//
//     #[test]
//     fn simple_node_data_block_comparisons() {
//         let keys = crypto::sign::gen_keypair();
//         let test_data1 = BlockIdentifier::Type1(1u64);
//         let test_data2 = BlockIdentifier::Type1(1u64);
//         let test_data3 = BlockIdentifier::Type2(1u64);
//         let test_node_data_block1 = NodeBlock::new(&keys.0, &keys.1, test_data1).expect("fail1");
//         let test_node_data_block2 = NodeBlock::new(&keys.0, &keys.1, test_data2).expect("fail2");
//         let test_node_data_block3 = NodeBlock::new(&keys.0, &keys.1, test_data3).expect("fail3");
//         assert_eq!(test_node_data_block1.clone(), test_node_data_block2.clone());
//         assert!(test_node_data_block1 != test_node_data_block3.clone());
//         assert!(test_node_data_block2 != test_node_data_block3);
//
//     }
// }
//     fn create_data_chain(count: u64) -> DataChain {
//         let group_size = 8;
//         let mut chain = DataChain::new(group_size);
//
//         let keys = (0..count + group_size)
//             .map(|_| crypto::sign::gen_keypair())
//             .collect_vec();
//
//
//
//
//         let data_blocks = (0..count)
//             .map(|x| {
//                 let mut block = if x % 2 == 0 {
//                     Block::new(BlockIdentifier::Type1(x))
//                 } else {
//                     Block::new(BlockIdentifier::Type2(x))
//                 };
//                 let data = serialisation::serialise(&block.identifier).expect("serialise fail");
//                 for y in 0..group_size {
//                     let _ = block.add_node(keys[x as usize + y as usize].0,
//                                            crypto::sign::sign_detached(&data[..],
//                                                                        &keys[x as usize +
//                                                                              y as usize]
//                                                                            .1));
//                 }
//                 block
//             })
//             .collect_vec();
//
//         let now = time::Instant::now();
//
//         for i in data_blocks.iter() {
//             chain.add_block(i.clone()).expect("chain fill failed");
//         }
//         println!("Took {:?}.{:?} seconds to add {:?} blocks",
//                  now.elapsed().as_secs(),
//                  now.elapsed().subsec_nanos(),
//                  chain.len());
//         chain
//     }
//
//     #[test]
//     fn create_and_validate_chain() {
//         let count = 1000;
//         let mut chain = create_data_chain(count);
//
//         let now1 = time::Instant::now();
//         let _ = chain.validate().expect("validate failed");
//         println!("Took {:?}.{:?} seconds to validate  {:?} blocks",
//                  now1.elapsed().as_secs(),
//                  now1.elapsed().subsec_nanos(),
//                  count);
//
//     }
//
//
//     #[test]
//     fn delete_all_and_validate() {
//         let count = 100i64;
//         let mut chain = create_data_chain(count as u64);
//
//         assert_eq!(chain.len(), count as usize);
//         assert_eq!(chain.chain.iter().map(|x| !x.deleted).count(),
//                    count as usize);
//
//         for i in 0..count {
//             let _ = chain.delete(i as u64);
//         }
//
//         // internally all entries there, but marked deleted (entry 0 removed)
//         assert_eq!(chain.chain.iter().map(|x| x.deleted).count(), 0);
//         assert_eq!(chain.len(), 0);
//         assert!(chain.empty());
//     }
//
//     #[test]
//     fn delete_rev_and_validate() {
//         let count = 100i64;
//         let mut chain = create_data_chain(count as u64);
//
//         assert_eq!(chain.len(), count as usize);
//         assert_eq!(chain.chain.iter().map(|x| !x.deleted).count(),
//                    count as usize);
//
//         for i in count..0 {
//             let _ = chain.delete(i as u64);
//         }
//         let _ = chain.delete(0);
//         // internally all entries there, but marked deleted (entry 0 removed)
//         assert_eq!(chain.chain.iter().map(|x| x.deleted).count() + 1,
//                    count as usize);
//         assert_eq!(chain.len() + 1, count as usize);
//         assert!(!chain.empty());
//         let _ = chain.validate().expect("validate failed");
//
//     }
//
//
//
// }
