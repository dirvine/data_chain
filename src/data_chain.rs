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


use itertools::Itertools;
use block::Block;
use block_identifier::BlockIdentifier;
use node_block::NodeBlock;
use sodiumoxide::crypto::sign::PublicKey;
use error::Error;

/// Created by holder of chain, can be passed to others as proof of data held.
/// This object is verifiable if :
/// The last validation contains the majority of current close group
/// OR on network restart the nodes all must try and restart on
/// previous names. They can continue any validation of the holder of a chain.
/// This requires nodes to always restart as last ID and if there was no restart they are rejected
/// at vault level.
/// If there was a restart then the nodes should validate and continue.
/// N:B this means all nodes can use a named directory for data store and clear if they restart
/// as a new id. This allows clean-up of old data cache directories.
#[derive(Default, Debug, PartialEq, RustcEncodable, RustcDecodable)]
pub struct DataChain {
    chain: Vec<Block>,
}

impl DataChain {
    /// Nodes always validate a chain before accepting it
    /// Validation takes place from start of chain to now.
    /// Also confirm we can accept this chain, by comparing
    /// our current group with the majority of the last known link
    /// This method will purge all not yet valid blocks
    pub fn validate_ownership(&mut self, my_group: &[PublicKey]) -> bool {
        // ensure all links are good
        self.mark_blocks_valid();
        // ensure last good ink contains majority of current group
        if let Some(last_link) = self.last_valid_link() {
            return (last_link.proof().iter()
                .filter(|k| my_group.iter().any(|&z| PublicKey(z.0) == k.0))
                .count() * 2) > last_link.proof().len();

        } else {
            false
        }
    }

    /// Add a nodeblock received from a peer
    /// We do not validate the block, it may be out of order
    /// This is a case of `lazy accumulation`
    pub fn add_node_block(&mut self, block: NodeBlock) -> Result<(), Error> {
        if !block.validate() {
            return Err(Error::Validation);
        }
        if self.chain
            .iter_mut()
            .find(|x| x.identifier() == block.identifier())
            .map(|x| x.add_proof(block.proof().clone())).is_some() //; if self.validate_block(x) { x.valid = true; }
// x }).is_some()
          {
            return Ok(());
            }
        let blk = try!(Block::new(block));
        self.chain.push(blk);
        Ok(())

    }

    /// Validate an individual block. Will get latest link and confirm all signatures
    /// were from last known valid group.
    pub fn validate_block(&mut self, block: &mut Block) -> bool {
        if let Some(ref mut link) = self.last_valid_link() {
            return Self::validate_block_with_proof(block, link);
        }
        false
    }

    /// Remove all invalid blocks, does not confirm chain is valid to this group.
    pub fn prune(&mut self) {
        self.mark_blocks_valid();
        self.chain.retain(|x| x.valid);
    }

    /// Total length of chain
    pub fn len(&self) -> usize {
        self.chain.len()
    }
    /// Total length of chain
    pub fn valid_len(&self) -> usize {
        self.blocks_len() + self.links_len()
    }
    /// number of  blocks
    pub fn blocks_len(&self) -> usize {
        self.chain.iter().filter(|x| x.identifier().is_block() && x.valid).count()
    }
    /// number of links
    pub fn links_len(&self) -> usize {
        self.chain.iter().filter(|x| x.identifier().is_link() && x.valid).count()
    }

    /// Contains no blocks that are not valid
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }

    /// Remove a block, will ignore Links
    pub fn remove(&mut self, data_id: BlockIdentifier) {
        self.chain.retain(|x| x.identifier() != &data_id || x.identifier().is_link());

    }

    /// Should contain majority of the current common_close_group
    fn last_valid_link(&mut self) -> Option<&mut Block> {
        self.chain.iter_mut().rev().find((|x| x.identifier().is_link() && x.valid))
    }

    /// Return all links in chain
    /// Does not perform validation on links
    pub fn get_all_links(&self) -> DataChain {
        DataChain {
            chain: self.chain
                .iter()
                .cloned()
                .filter(|x| x.identifier().is_link())
                .collect_vec(),
        }

    }

    /// Validate and return all links in chain
    pub fn get_all_valid_links(&mut self) -> DataChain {
        self.mark_blocks_valid();
        DataChain {
            chain: self.chain
                .iter()
                .cloned()
                .filter(|x| x.identifier().is_link() && x.valid)
                .collect_vec(),
        }

    }

    /// Mark all links that are valid as such.
    pub fn mark_blocks_valid(&mut self) {
        if let Some(mut first_link) = self.chain
            .iter()
            .cloned()
            .find(|x| x.identifier().is_link()) {
            for block in self.chain.iter_mut() {
                if Self::validate_block_with_proof(block, &mut first_link) {
                    block.valid = true;
                    if block.identifier().is_link() {
                        first_link = block.clone();
                    }
                } else {
                    block.valid = false;
                }
            }
        } else {
            self.chain.clear();
        }
    }

    fn validate_block_with_proof(block: &mut Block, proof: &Block) -> bool {
        block.remove_invalid_signatures();
        proof.proof()
            .iter()
            .map(|x| x.0)
            .filter(|&y| block.proof().iter().map(|z| z.0).any(|p| p == y))
            .count() * 2 > proof.proof().len()
    }
}


#[cfg(test)]

mod tests {
    use super::*;
    use sodiumoxide::crypto;
    use itertools::Itertools;
    use node_block;
    use node_block::NodeBlock;
    use block_identifier::BlockIdentifier;

    // use std::time;

    #[test]
    fn link_only_chain() {
        ::sodiumoxide::init();
        let keys = (0..100)
            .map(|_| crypto::sign::gen_keypair())
            .collect_vec();
        // ########################################################################################
        // create groups of keys to resemble close_groups
        // ########################################################################################
        let pub1 = keys.iter().map(|x| x.0).take(3).collect_vec();
        let pub2 = keys.iter().map(|x| x.0).skip(1).take(3).collect_vec();
        let pub3 = keys.iter().map(|x| x.0).skip(2).take(3).collect_vec();
        assert!(pub1 != pub2);
        assert!(pub1 != pub3);
        assert!(pub1.len() == 3);
        assert!(pub2.len() == 3);
        assert!(pub3.len() == 3);
        // ########################################################################################
        // create link descriptors, which form the Block identifier
        // ########################################################################################
        let link_desc1 = node_block::create_link_descriptor(&pub1[..]);
        let link_desc2 = node_block::create_link_descriptor(&pub2[..]);
        let link_desc3 = node_block::create_link_descriptor(&pub3[..]);
        // ########################################################################################
        // The block  identifier is the part of a Block/NodeBlock that
        // describes the block, here it is links, but could be StructuredData / ImmutableData
        // ########################################################################################
        let identifier1 = BlockIdentifier::Link(link_desc1);
        let identifier2 = BlockIdentifier::Link(link_desc2);
        let identifier3 = BlockIdentifier::Link(link_desc3);
        assert!(identifier1 != identifier2);
        assert!(identifier1 != identifier3);
        assert!(identifier2 != identifier3);
        // ########################################################################################
        // Create NodeBlocks, these are what nodes send to each other
        // Here they are all links only. For Put Delete Post
        // these would be Identifiers for the data types that includes a hash of the serialised data
        // ########################################################################################
        let link1_1 = NodeBlock::new(&keys[0].0, &keys[0].1, identifier1.clone());
        let link1_2 = NodeBlock::new(&keys[1].0, &keys[1].1, identifier1.clone());
        let link1_3 = NodeBlock::new(&keys[2].0, &keys[2].1, identifier1);
        let link2_1 = NodeBlock::new(&keys[1].0, &keys[1].1, identifier2.clone());
        // here we need to add 2_1 again as 2_1 will be purged as part of test later on
        let link2_1_again_1 = NodeBlock::new(&keys[1].0, &keys[1].1, identifier2.clone());
        let link2_1_again_2 = NodeBlock::new(&keys[1].0, &keys[1].1, identifier2.clone());
        let link2_2 = NodeBlock::new(&keys[2].0, &keys[2].1, identifier2.clone());
        let link2_3 = NodeBlock::new(&keys[3].0, &keys[3].1, identifier2);
        let link3_1 = NodeBlock::new(&keys[2].0, &keys[2].1, identifier3.clone());
        let link3_2 = NodeBlock::new(&keys[3].0, &keys[3].1, identifier3.clone());
        let link3_3 = NodeBlock::new(&keys[4].0, &keys[4].1, identifier3);
        assert!(link1_1.is_ok());
        assert!(link1_2.is_ok());
        assert!(link1_3.is_ok());
        assert!(link2_1.is_ok());
        assert!(link2_2.is_ok());
        assert!(link2_3.is_ok());
        assert!(link3_1.is_ok());
        assert!(link3_2.is_ok());
        assert!(link3_3.is_ok());
        // #################### Create chain ########################
        let mut chain = DataChain::default();
        assert!(chain.is_empty());
        // ############# start adding blocks #####################
        assert!(chain.add_node_block(link1_1.unwrap()).is_ok());
        assert!(chain.validate_ownership(&pub1)); // 1 link - all OK
        assert_eq!(chain.len(), 1);
        assert!(chain.add_node_block(link1_2.unwrap()).is_ok());
        assert!(chain.add_node_block(link1_3.unwrap()).is_ok());
        // ########################################################################################
        // pune_and_validate will prune any invalid data, In first link all data is valid if sig OK
        // ########################################################################################
        assert!(chain.validate_ownership(&pub1));
        assert!(!chain.validate_ownership(&pub3));
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.blocks_len(), 0);
        assert_eq!(chain.links_len(), 1);
        assert!(chain.add_node_block(link2_1.unwrap()).is_ok());
        // ########################################################################################
        // Ading a link block will not increase length of chain links as it's not yet valid
        // ########################################################################################
        assert_eq!(chain.links_len(), 1);
        let chain_links1 = chain.get_all_links();
        assert_eq!(chain, chain_links1); // includes invalid (yet) links
        // ########################################################################################
        // The call below will mark 2_1 as invalid as it is a new link without majority agreement
        // ########################################################################################
        let chain_valid_links1 = chain.get_all_valid_links();
        assert_eq!(chain.links_len(), 1);
        assert_eq!(chain.len(), 2); // contains an invalid link for now
        assert_eq!(chain.valid_len(), 1);
        assert!(chain != chain_valid_links1); // will see 2nd link as not yet valid and remove  it
        assert!(chain.add_node_block(link2_1_again_1.unwrap()).is_ok()); // re-add 2.1
        // ########################################################################################
        // The call below will prune 2_1 as it is a new link without majority agreement
        // ########################################################################################
        assert!(chain.validate_ownership(&pub2));
        assert_eq!(chain.links_len(), 1); //  we pruned link2_1_again in validate_ownership call
        assert!(chain.add_node_block(link2_1_again_2.unwrap()).is_ok()); // re-add 2.1
        assert!(chain.add_node_block(link2_2.unwrap()).is_ok());
        assert!(chain.validate_ownership(&pub2)); // Ok as now 2 is in majority
        assert_eq!(chain.links_len(), 2);
        assert_eq!(chain.len(), 2);
        assert!(chain.add_node_block(link2_3.unwrap()).is_ok());
        assert!(chain.validate_ownership(&pub2));
        assert!(chain.add_node_block(link3_1.unwrap()).is_ok());
        assert!(chain.add_node_block(link3_2.unwrap()).is_ok());
        assert!(chain.add_node_block(link3_3.unwrap()).is_ok());
        assert!(chain.validate_ownership(&pub3));
        assert!(!chain.validate_ownership(&pub1));
        let chain_links = chain.get_all_links();
        assert_eq!(chain, chain_links);
        let chain_valid_links = chain.get_all_valid_links();
        assert_eq!(chain, chain_valid_links);
        assert_eq!(chain.len(), 3);
        assert!(!chain.is_empty());
        assert_eq!(chain.blocks_len(), 0);
        assert_eq!(chain.links_len(), 3);
        chain.prune();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain.blocks_len(), 0);
        assert_eq!(chain.links_len(), 3);

    }
}

