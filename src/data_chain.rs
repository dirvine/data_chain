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
use block::Block;
use block_identifier::BlockIdentifier;
use node_block::NodeBlock;
// use sodiumoxide::crypto;
// use sodiumoxide::crypto::hash::sha256::Digest;
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
        if !self.validate_all_links() {
            return Err(Error::Validation);
        }
        // [TODO]: Validate all blocks - 2016-05-31 01:18am
        Ok(())
    }


    /// Add a nodeblock recived from a peer
    pub fn add_node_block(&mut self, block: NodeBlock) -> Result<(), Error> {
        if !block.validate() {
            return Err(Error::Validation);
        }
        if self.chain.iter_mut().find(|x| x.identifier() == block.identifier()).map(|x| x.add_proof(block.proof().clone())).is_some() {
            return Ok(());
        }
            let blk = try!(Block::new(block));
            self.chain.push(blk);
        Ok(())

    }


    /// number of  blocks
    pub fn len(&self) -> usize {
        self.chain.len()
    }
    /// number of  blocks
    pub fn blocks_len(&self) -> usize {
        self.chain.iter().filter(|x| x.identifier().is_block()).count()
    }
    /// number of  blocks
    pub fn links_len(&self) -> usize {
        self.chain.iter().filter(|x| x.identifier().is_link()).count()
    }

    /// Contains no blocks that are not deleted
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    /// Delete a block (will not delete a link)
    pub fn delete(&mut self, data_id: BlockIdentifier) {
        self.chain.retain(|x| {
            x.identifier() != &data_id || x.identifier().is_link()
        });

    }


    /// Should equal the current common_close_group
    pub fn get_last_link(&self) -> Option<&Block> {
        self.chain.iter().rev().find((|&x| x.identifier().is_link()))
    }

    /// Find block from top and get next link
    fn get_recent_link(&self, block: &Block) -> Option<&Block> {
        self.chain
            .iter()
            .rev()
            .skip_while(|x| x.identifier() != block.identifier())
            .find((|&x| x.identifier().is_link()))
    }

    /// nsValidate all links in chain
    fn validate_all_links(&self) -> bool {
        let one = self.chain
            .iter()
            .filter(|&x| x.identifier().is_link() && x.validate_block_signatures())
            .rev()
            .into_rc();

        one.clone().zip(one.clone()).all(|x| {
            x.0.proof()
                .iter()
                .filter(|k| x.1.proof().contains_key(k.0))
                .count() * 2 > ::GROUP_SIZE
        })
    }

    /// Validate an individual block. Will get latest link and confirm all signatures
    /// were from last known group. Majority of sigs is confirmed.
    pub fn validate_block(&self, block: &Block) -> Result<(), Error> {
        if let Some(ref link) = self.get_recent_link(block) {
            try!(self.validate_block_with_proof(block, &link))
        }
        return Err(Error::NoLink);
    }

    fn validate_block_with_proof(&self, block: &Block, proof: &Block) -> Result<(), Error> {
        let _id = try!(serialisation::serialise(block.identifier()));
        if !proof.identifier().is_link() {
        return Err(Error::Majority);
    }
    Ok(())
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
