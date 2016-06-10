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

use std::slice::{Split, SplitMut, SplitN, SplitNMut, RSplitN, RSplitNMut};
use itertools::Itertools;
use block::Block;
use block_identifier::BlockIdentifier;
use node_block::NodeBlock;
use node_block;
use sodiumoxide::crypto::sign::PublicKey;

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
    /// This method will NOT purge
    pub fn validate_ownership(&mut self, my_group: &[PublicKey]) -> bool {
        // ensure all links are good
        self.mark_blocks_valid();
        // ensure last good ink contains majority of current group
        if let Some(last_link) = self.last_valid_link() {
            return (last_link.proof()
                .iter()
                .filter(|k| my_group.iter().any(|&z| PublicKey(z.0) == k.0))
                .count() * 2) > last_link.proof().len();

        } else {
            false
        }
    }

    /// Add a nodeblock received from a peer
    /// Uses  `lazy accumulation`
    /// If block becomes or is valid, then it is returned
    pub fn add_node_block(&mut self, block: NodeBlock) -> Option<BlockIdentifier> {
        if !block.validate() {
            return None;
        }
        let len; // first link in chain must be considered valid, we are creating this.
        {
            len = self.len();
        }
        {
            let mut iter = self.chain.iter_mut().rev().multipeek();
            'outer: while let Some(blk) = iter.next() {
                // just get first
                if blk.identifier() == block.identifier() {
                    if len == 1 {
                        let _ = blk.add_proof(block.proof().clone());
                        return None;
                    }
                    // in this case we have encountered a possible duplicate link
                    // (group) go for new link
                    if blk.identifier().is_link() && Self::link_locked(blk) {
                        blk.valid = true;
                        continue;
                    }
                    while let Some(link) = iter.peek() {

                        if link.identifier().is_link()
                        // && link.valid
                        {

                            // Do not allow blocks to be longer than previous valid link
                            // if link is locked
                            if blk.proof().len() >
                               if Self::link_locked(link) {
                                link.proof().len()
                            } else {
                                0
                            } {
                                continue 'outer;
                            } // again a duplicate
                            let _ = blk.add_proof(block.proof().clone());
                            if Self::validate_block_with_proof(blk, link) {
                                // we have the last good link
                                blk.valid = true;
                                break;
                            } else {
                                return None;
                            }
                        }
                    }
                    return Some(blk.identifier().clone());
                }
            }
        }
        if let Ok(blk) = Block::new(block) {
            self.chain.push(blk);
        }
        None

    }

    /// find a block (user required to test for validity)
    pub fn find(&self, block_identifier: &BlockIdentifier) -> Option<&Block> {
        self.chain.iter().find(|x| x.identifier() == block_identifier)
    }

    /// Extract slice containing entire chain
    pub fn as_slice(&self) -> &[Block] {
        self.chain.as_slice()
    }

    /// Extract mutable slice containing entire chain
    pub fn as_mut_slice(&mut self) -> &[Block] {
        self.chain.as_mut_slice()
    }

    /// Remove a block, will ignore Links
    pub fn remove(&mut self, data_id: &BlockIdentifier) {
        self.chain.retain(|x| x.identifier() != data_id || x.identifier().is_link());

    }

    /// Clear chain
    pub fn clear(&mut self) {
        self.chain.clear()
    }

    /// Check if chain contains a particular identifier
    pub fn contains(&self, block_identifier: &BlockIdentifier) -> bool {
        self.chain.iter().find(|x| x.identifier() == block_identifier).is_some()
    }

    /// Return position of block identifier
    pub fn position(&self, block_identifier: &BlockIdentifier) -> Option<usize> {
        self.chain.iter().position(|x| x.identifier() == block_identifier)
    }

    /// Inserts an element at position index within the chain, shifting all elements
    /// after it to the right.
    /// Will not validate this block!
    /// # Panics
    ///
    /// Panics if index is greater than the chains's length.
    pub fn insert(&mut self, index: usize, block: Block) {
        self.chain.insert(index, block)
    }

    /// Returns an iterator over subslices separated by elements that match pred.
    /// The matched element is not contained in the subslices.
    pub fn split<F>(&self, pred: F) -> Split<Block, F>
        where F: FnMut(&Block) -> bool
    {
        self.chain.split(pred)
    }

    /// Returns an iterator over subslices separated by elements that match pred.
    /// The matched element is not contained in the subslices.
    pub fn split_mut<F>(&mut self, pred: F) -> SplitMut<Block, F>
        where F: FnMut(&Block) -> bool
    {
        self.chain.split_mut(pred)
    }

    /// Returns an iterator over subslices separated by elements that match pred,
    /// limited to returning at most n items. The matched element is not contained in the subslices.
    /// The last element returned, if any, will contain the remainder of the slice.
    pub fn splitn<F>(&self, n: usize, pred: F) -> SplitN<Block, F>
        where F: FnMut(&Block) -> bool
    {
        self.chain.splitn(n, pred)
    }

    /// Returns an iterator over subslices separated by elements that match pred,
    /// limited to returning at most n items. The matched element is not contained in the subslices.
    /// The last element returned, if any, will contain the remainder of the slice.
    pub fn splitn_mut<F>(&mut self, n: usize, pred: F) -> SplitNMut<Block, F>
        where F: FnMut(&Block) -> bool
    {
        self.chain.splitn_mut(n, pred)
    }

    /// Splits the chain into two at the given index.
    /// Returns a newly allocated Self. chain contains elements [0, at), and the returned
    /// chain contains elements [at, len).
    /// Note that the capacity of chain does not change.]]
    pub fn split_off(&mut self, at: usize) -> Vec<Block> {
        self.chain.split_off(at)
    }

    /// Returns an iterator over subslices separated by elements that match pred limited to
    /// returning at most n items. This starts at the end of the slice and works backwards.
    /// The matched element is not contained in the subslices.
    /// The last element returned, if any, will contain the remainder of the slice.
    pub fn rsplitn<F>(&self, n: usize, pred: F) -> RSplitN<Block, F>
        where F: FnMut(&Block) -> bool
    {
        self.chain.rsplitn(n, pred)
    }

    /// Returns an iterator over subslices separated by elements that match pred limited to
    /// returning at most n items. This starts at the end of the slice and works backwards.
    /// The matched element is not contained in the subslices.
    /// The last element returned, if any, will contain the remainder of the slice.
    pub fn rsplitn_mut<F>(&mut self, n: usize, pred: F) -> RSplitNMut<Block, F>
        where F: FnMut(&Block) -> bool
    {
        self.chain.rsplitn_mut(n, pred)
    }


    // is link descriptor equal to all public keys xored together
    fn link_locked(link: &Block) -> bool {
        if link.identifier().is_block() {
            return false;
        }

        let keys = link.proof().iter().map(|x| x.0).collect_vec();
        node_block::create_link_descriptor(&keys[..]) == link.identifier().hash().0
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
    /// Number of valid blocks
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
                block.remove_invalid_signatures();
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

    fn validate_block_with_proof(block: &Block, proof: &Block) -> bool {
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
    use sodiumoxide::crypto::hash::sha256;
    use itertools::Itertools;
    use node_block;
    use node_block::NodeBlock;
    use block_identifier::BlockIdentifier;

    // use std::time;

    #[test]
    fn link_only_chain() {
        ::sodiumoxide::init();
        let keys = (0..10)
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
        assert!(chain.add_node_block(link1_1.unwrap()).is_none());
        assert!(chain.validate_ownership(&pub1)); // 1 link - all OK
        assert_eq!(chain.len(), 1);
        assert!(chain.add_node_block(link1_2.unwrap()).is_none());
        assert!(chain.add_node_block(link1_3.unwrap()).is_none());
        // ########################################################################################
        // pune_and_validate will prune any invalid data, In first link all data is valid if sig OK
        // ########################################################################################
        assert!(chain.validate_ownership(&pub1));
        assert!(!chain.validate_ownership(&pub3));
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.blocks_len(), 0);
        assert_eq!(chain.links_len(), 1);
        assert!(chain.add_node_block(link2_1.unwrap()).is_none());
        // ########################################################################################
        // Ading a link block will not increase length of chain links as it's not yet valid
        // ########################################################################################
        assert_eq!(chain.links_len(), 1);
        assert_eq!(chain.blocks_len(), 0);
        assert_eq!(chain, chain.get_all_links()); // includes invalid (yet) links
        // ########################################################################################
        // The call below will mark 2_1 as invalid as it is a new link without majority agreement
        // ########################################################################################
        let chain_valid_links1 = chain.get_all_valid_links();
        assert_eq!(chain.links_len(), 1);
        assert_eq!(chain.len(), 2); // contains an invalid link for now
        assert_eq!(chain.valid_len(), 1);
        assert!(chain != chain_valid_links1); // will see 2nd link as not yet valid and remove  it
        assert!(chain.add_node_block(link2_1_again_1.unwrap()).is_none()); // try re-add 2.1
        assert!(chain.validate_ownership(&pub2));
        assert_eq!(chain.links_len(), 1);
        assert!(chain.add_node_block(link2_1_again_2.unwrap()).is_none());
        assert!(chain.add_node_block(link2_2.unwrap()).is_some()); // majority reached here
        // assert!(chain.validate_ownership(&pub2)); // Ok as now 2 is in majority
        assert_eq!(chain.links_len(), 2);
        assert_eq!(chain.len(), 2);
        assert!(chain.add_node_block(link2_3.unwrap()).is_some());
        assert!(chain.validate_ownership(&pub2));
        assert!(chain.add_node_block(link3_1.unwrap()).is_none());
        assert!(chain.add_node_block(link3_2.unwrap()).is_some()); // majority reached here
        assert!(chain.add_node_block(link3_3.unwrap()).is_some());
        // ########################################################################################
        // Check blocks are validating as NodeBlocks are added, no need to call validate_all here,
        // should be automatic.
        // ########################################################################################
        assert_eq!(chain.links_len(), 3);
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

    #[test]
    fn single_link_chain() {
        ::sodiumoxide::init();
        let keys = (0..50)
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
        let link_desc1 = node_block::create_link_descriptor(&pub1[..]);
        let identifier1 = BlockIdentifier::Link(link_desc1);
        let id_ident = BlockIdentifier::ImmutableData(sha256::hash(b"id1hash"));
        let sd1_ident = BlockIdentifier::StructuredData(sha256::hash(b"sd1hash"),
                                                        sha256::hash(b"sd1name"),0, false);
        let sd2_ident = BlockIdentifier::StructuredData(sha256::hash(b"s21hash"),
                                                        sha256::hash(b"sd2name"),1 , true);
        assert!(identifier1 != id_ident);
        assert!(identifier1 != sd1_ident);
        assert!(id_ident != sd1_ident);
        assert!(sd1_ident != sd2_ident);
        // ########################################################################################
        // Create NodeBlocks, these are what nodes send to each other
        // Here they are all links only. For Put Delete Post
        // these would be Identifiers for the data types that includes a hash of the serialised data
        // ########################################################################################
        let link1_1 = NodeBlock::new(&keys[0].0, &keys[0].1, identifier1.clone());
        let link1_2 = NodeBlock::new(&keys[1].0, &keys[1].1, identifier1.clone());
        let link1_3 = NodeBlock::new(&keys[2].0, &keys[2].1, identifier1);
        let sd1_1 = NodeBlock::new(&keys[1].0, &keys[1].1, id_ident.clone());
        // here we need to add 2_1 again as 2_1 will be purged as part of test later on
        let sd1_1_again_1 = NodeBlock::new(&keys[1].0, &keys[1].1, id_ident.clone());
        let sd1_1_again_2 = NodeBlock::new(&keys[1].0, &keys[1].1, id_ident.clone());
        let sd1_2 = NodeBlock::new(&keys[2].0, &keys[2].1, id_ident.clone());
        let sd1_3 = NodeBlock::new(&keys[3].0, &keys[3].1, id_ident);
        let id_1 = NodeBlock::new(&keys[2].0, &keys[2].1, sd1_ident.clone());
        let id_2 = NodeBlock::new(&keys[3].0, &keys[3].1, sd1_ident.clone()); // fail w/wrong keys
        let id_3 = NodeBlock::new(&keys[4].0, &keys[4].1, sd1_ident); // fail w/wrong keys
        // #################### Create chain ########################
        let mut chain = DataChain::default();
        assert!(chain.is_empty());
        // ############# start adding link #####################
        assert!(chain.add_node_block(link1_1.unwrap()).is_none());
        assert!(chain.validate_ownership(&pub1)); // 1 link - all OK
        assert_eq!(chain.len(), 1);
        assert!(chain.add_node_block(link1_2.unwrap()).is_none());
        assert!(chain.validate_ownership(&pub1)); // 1 link - all OK
        assert_eq!(chain.len(), 1);
        assert!(chain.add_node_block(link1_3.unwrap()).is_none());
        assert!(chain.validate_ownership(&pub1)); // 1 link - all OK
        assert_eq!(chain.len(), 1);
        // ########################################################################################
        // pune_and_validate will prune any invalid data, In first link all data is valid if sig OK
        // ########################################################################################
        assert!(chain.validate_ownership(&pub1));
        assert!(!chain.validate_ownership(&pub3));
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.blocks_len(), 0);
        assert_eq!(chain.links_len(), 1);
        assert!(chain.add_node_block(sd1_1.unwrap()).is_none());
        // ########################################################################################
        // Ading a link block will not increase length of chain links as it's not yet valid
        // ########################################################################################
        assert_eq!(chain.links_len(), 1);
        assert_eq!(chain.len(), 2); // contains an invalid link for now
        assert_eq!(chain.valid_len(), 1);
        assert!(chain.add_node_block(sd1_1_again_1.unwrap()).is_none()); // re-add 2.1
        // ########################################################################################
        // The call below will prune 2_1 as it is a new link without majority agreement
        // ########################################################################################
        assert!(chain.validate_ownership(&pub2));
        assert_eq!(chain.links_len(), 1);
        assert!(chain.add_node_block(sd1_1_again_2.unwrap()).is_none()); // re-add 2.1
        assert!(chain.add_node_block(sd1_2.unwrap()).is_some()); // majority reached here
        assert!(chain.validate_ownership(&pub2)); // Ok as now 2 is in majority
        assert_eq!(chain.links_len(), 1);
        assert_eq!(chain.blocks_len(), 1);
        assert_eq!(chain.len(), 2);
        assert!(chain.add_node_block(sd1_3.unwrap()).is_some());
        assert!(chain.validate_ownership(&pub2));
        assert_eq!(chain.links_len(), 1);
        assert_eq!(chain.blocks_len(), 1);
        assert_eq!(chain.len(), 2);
        // the call below will not add any links
        let id1 = id_1.unwrap();
        assert!(chain.add_node_block(id1.clone()).is_none()); // only 1st id has valid signature
        assert!(chain.add_node_block(id_3.unwrap()).is_none()); // will not get majority
        assert!(chain.add_node_block(id_2.unwrap()).is_none());
        assert_eq!(chain.links_len(), 1);
        assert_eq!(chain.blocks_len(), 1);
        assert_eq!(chain.len(), 3);
        chain.prune();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain.valid_len(), 2);
        assert!(chain.add_node_block(id1.clone()).is_none());
        assert_eq!(chain.len(), 3);
        assert_eq!(chain.valid_len(), 2);
        chain.remove(id1.identifier());
        assert_eq!(chain.len(), 2);
        assert!(chain.add_node_block(id1.clone()).is_none());
        assert_eq!(chain.len(), 3);
        assert_eq!(chain.valid_len(), 2);

    }
}
