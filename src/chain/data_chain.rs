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

use chain::block::Block;
use chain::block_identifier::BlockIdentifier;
use chain::node_block::NodeBlock;
use error::Error;
use fs2::FileExt;
use itertools::Itertools;
use maidsafe_utilities::serialisation;
use rust_sodium::crypto::sign::PublicKey;
use std::fs;
use std::io::{self, Read, Write};
use std::mem;
use std::path::PathBuf;

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
    group_size: usize,
    path: Option<PathBuf>,
}

type Blocks = Vec<Block>;

impl DataChain {
    /// Create a new chain backed up on disk
    /// Provide the directory to create the files in
    pub fn create_in_path(path: PathBuf, group_size: usize) -> io::Result<DataChain> {
        let path = path.join("data_chain");
        let file = try!(fs::OpenOptions::new().read(true).write(true).create_new(true).open(&path));
        // hold a lock on the file for the whole session
        try!(file.lock_exclusive());
        Ok(DataChain {
            chain: Blocks::default(),
            group_size: group_size,
            path: Some(path),
        })
    }
    /// Open from existing directory
    pub fn from_path(path: PathBuf, group_size: usize) -> Result<DataChain, Error> {
        let path = path.join("data_chain");
        let mut file =
            try!(fs::OpenOptions::new().read(true).write(true).create(false).open(&path));
        // hold a lock on the file for the whole session
        try!(file.lock_exclusive());
        let mut buf = Vec::<u8>::new();
        let _ = try!(file.read_to_end(&mut buf));
        Ok(DataChain {
            chain: try!(serialisation::deserialise::<Blocks>(&buf[..])),
            group_size: group_size,
            path: Some(path),
        })
    }

    /// Create chain in memory from vector of blocks
    pub fn from_blocks(blocks: Vec<Block>, group_size: usize) -> DataChain {
        DataChain {
            chain: blocks,
            group_size: group_size,
            path: None,
        }
    }

    /// Write current data chain to supplied path
    pub fn write(&self) -> Result<(), Error> {
        if let Some(path) = self.path.to_owned() {
            let mut file = try!(fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(false)
                .open(&path.as_path()));
            return Ok(try!(file.write_all(&try!(serialisation::serialise(&self.chain)))));
        }
        Err(Error::NoFile)
    }

    /// Write current data chain to supplied path
    pub fn write_to_new_path(&mut self, path: PathBuf) -> Result<(), Error> {
        let mut file = try!(fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(path.as_path()));
        try!(file.write_all(&try!(serialisation::serialise(&self.chain))));
        self.path = Some(path);
        Ok(try!(file.lock_exclusive()))
    }

    /// Unlock the lock file
    pub fn unlock(&self) {
        if let Some(ref path) = self.path.to_owned() {
            if let Ok(file) = fs::File::open(path.as_path()) {
                let _ = file.unlock();
            }
        }
    }

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
                .filter(|&k| my_group.iter().any(|&z| PublicKey(z.0) == *k.key()))
                .count() * 2) > last_link.proof().len();

        } else {
            false
        }
    }

    /// Add a nodeblock received from a peer
    /// Uses  `lazy accumulation`
    /// If block becomes valid, then it is returned
    pub fn add_node_block(&mut self, block: NodeBlock) -> Option<BlockIdentifier> {
        if !block.validate() {
            return None;
        }
        let len;
        let links;
        let group_size;
        {
            links = self.valid_links_at_block_id(block.identifier());
            len = self.chain.len();
            group_size = self.group_size;
            if self.chain.is_empty() {
                if let Ok(blk) = Block::new(block.clone()) {
                    self.chain.push(blk);
                    return None;
                }
            }
        }
        for blk in &mut self.chain {
            if blk.identifier() == block.identifier() {
                if blk.proof().iter().any(|x| x.key() == block.proof().key()) {
                    return None;
                }

                let _ = blk.add_proof(block.proof().clone());

                if len == 1 ||
                   links.iter()
                    .filter(|x| x.identifier() != blk.identifier())
                    .any(|y| Self::validate_block_with_proof(blk, y, group_size)) {
                    blk.valid = true;
                    return Some(blk.identifier().clone());
                } else {
                    blk.valid = false;
                    return None;
                }
            }
        }
        if let Ok(blk) = Block::new(block) {
            self.chain.push(blk);
        }
        None

    }

    /// getter
    pub fn chain(&self) -> &Vec<Block> {
        &self.chain
    }

    // get size of chain for storing on disk
    #[allow(unused)]
    fn size_of(&self) -> usize {
        self.chain.capacity() * (mem::size_of::<Block>() + (mem::size_of::<usize>() * 2))
    }

    /// find a block (user required to test for validity)
    pub fn find(&self, block_identifier: &BlockIdentifier) -> Option<&Block> {
        self.chain.iter().find(|x| x.identifier() == block_identifier)
    }

    /// find block by name from top (only first occurrence)
    pub fn find_name(&self, name: &[u8]) -> Option<&Block> {
        self.chain.iter().rev().find(|x| {
            x.valid &&
            if let Some(y) = x.identifier().name() {
                y == name
            } else {
                false
            }
        })
    }

    /// Remove a block, will ignore Links
    pub fn remove(&mut self, data_id: &BlockIdentifier) {
        self.chain.retain(|x| x.identifier() != data_id || x.identifier().is_link());
    }

    /// Retains only the blocks specified by the predicate.
    pub fn retain<F>(&mut self, pred: F)
        where F: FnMut(&Block) -> bool
    {
        self.chain.retain(pred);
    }

    /// Clear chain
    pub fn clear(&mut self) {
        self.chain.clear()
    }

    /// Check if chain contains a particular identifier
    pub fn contains(&self, block_identifier: &BlockIdentifier) -> bool {
        self.chain.iter().any(|x| x.identifier() == block_identifier)
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
    /// Panics if index is greater than the chains length.
    pub fn insert(&mut self, index: usize, block: Block) {
        self.chain.insert(index, block)
    }

    /// Validates an individual block. Will get latest link and confirm all signatures
    /// were from last known valid group.
    pub fn validate_block(&mut self, block: &mut Block) -> bool {
        for link in &self.valid_links_at_block_id(block.identifier()) {
            if Self::validate_block_with_proof(block, link, self.group_size) {
                return true;
            }
        }
        false
    }

    /// Removes all invalid blocks, does not confirm chain is valid to this group.
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

    /// number of valid data blocks
    pub fn blocks_len(&self) -> usize {
        self.chain.iter().filter(|x| x.identifier().is_block() && x.valid).count()
    }

    /// number of valid links
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

    /// Returns all links in chain
    /// Does not perform validation on links
    pub fn all_links(&self) -> Vec<Block> {
        self.chain
            .iter()
            .cloned()
            .filter(|x| x.identifier().is_link())
            .collect_vec()
    }

    /// Validates and returns all links in chain
    pub fn valid_data(&mut self) -> Vec<Block> {
        self.mark_blocks_valid();
        self.chain
            .iter()
            .cloned()
            .filter(|x| !x.identifier().is_link() && x.valid)
            .collect_vec()
    }

    /// Validates and returns all links in chain
    pub fn valid_links(&mut self) -> Vec<Block> {
        self.mark_blocks_valid();
        self.chain
            .iter()
            .cloned()
            .filter(|x| x.identifier().is_link() && x.valid)
            .collect_vec()
    }

    /// Validates and returns all valid links in chain 4 before and after target
    pub fn valid_links_at_block_id(&mut self, block_id: &BlockIdentifier) -> Vec<Block> {
        // FIXME the value of 4 is arbitrary
        // instead the length of last link len() should perhaps be used
        let top_links = self.chain
            .iter()
            .cloned()
            .skip_while(|x| x.identifier() != block_id)
            .filter(|x| x.identifier().is_link() && x.valid)
            .take(4)
            .collect_vec();

        let mut bottom_links = self.chain
            .iter()
            .rev()
            .cloned()
            .skip_while(|x| x.identifier() != block_id)
            .filter(|x| x.identifier().is_link() && x.valid)
            .take(4)
            .collect_vec();
        bottom_links.extend(top_links);

        bottom_links

    }


    /// Mark all links that are valid as such.
    pub fn mark_blocks_valid(&mut self) {
        if let Some(mut first_link) = self.chain
            .iter()
            .cloned()
            .find(|x| x.identifier().is_link()) {
            for block in &mut self.chain {
                block.remove_invalid_signatures();
                if Self::validate_block_with_proof(block, &first_link, self.group_size) {
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

    /// Merge any blocks from a given chain
    pub fn merge_chain(&mut self, chain: &mut DataChain) {
        chain.mark_blocks_valid();
        chain.prune();
        let mut start_pos = 0;
        for new in chain.chain().iter().filter(|x| x.identifier().is_block()) {
            let mut insert = false;
            for (pos, val) in self.chain.iter().skip(start_pos).enumerate() {
                if DataChain::validate_block_with_proof(new, val, self.group_size) {
                    start_pos = pos;
                    insert = true;
                    break;
                }
            }

            if insert {
                self.chain.insert(start_pos, new.clone());
                start_pos += 1;
            }
        }
    }

    fn validate_block_with_proof(block: &Block, proof: &Block, group_size: usize) -> bool {
        let p_len = proof.proof()
            .iter()
            .filter(|&y| block.proof().iter().any(|p| p.key() == y.key()))
            .count();
        (p_len * 2 > proof.proof().len()) || (p_len == group_size)
    }
}


#[cfg(test)]

mod tests {
    use chain::block::Block;
    use chain::block_identifier::BlockIdentifier;
    use chain::node_block;
    use chain::node_block::NodeBlock;
    use itertools::Itertools;
    use rust_sodium::crypto;
    use sha3::hash;
    use super::*;
    use tempdir::TempDir;

    #[test]
    fn validate_with_proof() {
        ::rust_sodium::init();
        let keys = (0..10)
            .map(|_| crypto::sign::gen_keypair())
            .collect_vec();
        let pub1 = keys.iter().map(|x| x.0).take(3).collect_vec();
        let pub2 = keys.iter().map(|x| x.0).skip(1).take(3).collect_vec();
        let link_desc1 = node_block::create_link_descriptor(&pub1[..]).unwrap();
        let link_desc2 = node_block::create_link_descriptor(&pub2[..]).unwrap();
        let identifier1 = BlockIdentifier::Link(link_desc1);
        let identifier2 = BlockIdentifier::Link(link_desc2);
        let identifier3 = BlockIdentifier::ImmutableData(hash(b"a"));
        let link1_1 = NodeBlock::new(&keys[0].0, &keys[0].1, identifier1.clone());
        let link1_2 = NodeBlock::new(&keys[1].0, &keys[1].1, identifier1.clone());
        let link1_3 = NodeBlock::new(&keys[2].0, &keys[2].1, identifier1);
        let link2_1 = NodeBlock::new(&keys[1].0, &keys[1].1, identifier2.clone());
        let link2_2 = NodeBlock::new(&keys[2].0, &keys[2].1, identifier2.clone());
        let link2_3 = NodeBlock::new(&keys[3].0, &keys[3].1, identifier2);
        let id1 = NodeBlock::new(&keys[2].0, &keys[2].1, identifier3.clone());
        let id2 = NodeBlock::new(&keys[3].0, &keys[3].1, identifier3.clone());
        let id3 = NodeBlock::new(&keys[4].0, &keys[4].1, identifier3);

        let mut block1 = Block::new(link1_1.unwrap()).unwrap();
        assert!(block1.add_proof(link1_2.unwrap().proof().clone()).is_ok());
        assert!(block1.add_proof(link1_3.unwrap().proof().clone()).is_ok());

        let mut block2 = Block::new(link2_1.unwrap()).unwrap();
        assert!(!DataChain::validate_block_with_proof(&block2, &block1, 999));
        assert!(block2.add_proof(link2_2.unwrap().proof().clone()).is_ok());
        assert!(DataChain::validate_block_with_proof(&block2, &block1, 999));
        assert!(block2.add_proof(link2_3.unwrap().proof().clone()).is_ok());
        assert!(DataChain::validate_block_with_proof(&block2, &block1, 999));

        let mut block3 = Block::new(id1.unwrap()).unwrap();
        assert!(!DataChain::validate_block_with_proof(&block3, &block2, 999));
        assert!(block3.add_proof(id2.unwrap().proof().clone()).is_ok());
        assert!(DataChain::validate_block_with_proof(&block3, &block2, 999));
        assert!(block3.add_proof(id3.unwrap().proof().clone()).is_ok());
        assert!(DataChain::validate_block_with_proof(&block3, &block2, 999));
    }

    #[test]
    fn link_only_chain() {
        ::rust_sodium::init();
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
        let link_desc1 = node_block::create_link_descriptor(&pub1[..]).unwrap();
        let link_desc2 = node_block::create_link_descriptor(&pub2[..]).unwrap();
        let link_desc3 = node_block::create_link_descriptor(&pub3[..]).unwrap();
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
        assert!(chain.add_node_block(link1_2.unwrap()).is_some());
        assert_eq!(chain.len(), 1);
        assert!(chain.add_node_block(link1_3.unwrap()).is_some());
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.len(), 1);
        // ########################################################################################
        // pune_and_validate will prune any invalid data, In first link all data is valid if sig OK
        // ########################################################################################
        assert!(chain.validate_ownership(&pub1));
        assert!(!chain.validate_ownership(&pub3));
        assert_eq!(chain.len(), 1);
        assert_eq!(chain.blocks_len(), 0);
        assert_eq!(chain.links_len(), 1);
        assert!(chain.add_node_block(link2_1.unwrap()).is_none());
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
        let chain_links = chain.all_links();
        assert_eq!(chain.chain, chain_links);
        let chain_valid_links = chain.valid_links();
        assert_eq!(chain.chain, chain_valid_links);
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
    fn data_link_chain() {
        ::rust_sodium::init();
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
        let link_desc1 = node_block::create_link_descriptor(&pub1[..]).unwrap();
        let identifier1 = BlockIdentifier::Link(link_desc1);
        let id_ident = BlockIdentifier::ImmutableData(hash(b"id1hash"));
        let sd1_ident = BlockIdentifier::StructuredData(hash(b"sd1hash"), hash(b"sd1name"), false);
        let sd2_ident = BlockIdentifier::StructuredData(hash(b"s21hash"), hash(b"sd2name"), true);
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
        let sd1_1 = NodeBlock::new(&keys[1].0, &keys[1].1, sd1_ident.clone());
        let sd1_2 = NodeBlock::new(&keys[2].0, &keys[2].1, sd1_ident.clone());
        let sd1_3 = NodeBlock::new(&keys[3].0, &keys[3].1, sd1_ident);
        let id_1 = NodeBlock::new(&keys[2].0, &keys[2].1, id_ident.clone());
        let id_2 = NodeBlock::new(&keys[1].0, &keys[1].1, id_ident.clone()); // fail w/wrong keys
        let id_3 = NodeBlock::new(&keys[4].0, &keys[4].1, id_ident); // fail w/wrong keys
        // #################### Create chain ########################
        let mut chain = DataChain::default();
        assert!(chain.is_empty());
        // ############# start adding link #####################
        assert!(chain.add_node_block(link1_1.unwrap()).is_none());
        assert!(chain.validate_ownership(&pub1));
        assert_eq!(chain.len(), 1);
        assert!(chain.add_node_block(link1_2.unwrap()).is_some());
        assert!(chain.validate_ownership(&pub1));
        assert_eq!(chain.len(), 1);
        assert!(chain.add_node_block(link1_3.unwrap()).is_some());
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
        assert!(chain.add_node_block(sd1_2.unwrap()).is_some());
        assert_eq!(chain.len(), 2);
        assert_eq!(chain.valid_len(), 2);
        assert!(chain.validate_ownership(&pub2)); // Ok as now 2 is in majority
        assert_eq!(chain.links_len(), 1);
        assert_eq!(chain.blocks_len(), 1);
        assert_eq!(chain.len(), 2);
        assert!(chain.add_node_block(sd1_3.unwrap()).is_some());
        assert!(chain.validate_ownership(&pub2));
        assert_eq!(chain.links_len(), 1);
        assert_eq!(chain.blocks_len(), 1);
        assert_eq!(chain.len(), 2);
        let id1 = id_1.unwrap();
        assert!(chain.add_node_block(id1.clone()).is_none()); // only 1st id has valid signature
        assert!(chain.add_node_block(id_2.unwrap()).is_some()); // will not get majority
        assert!(chain.add_node_block(id_3.unwrap()).is_some());
        assert_eq!(chain.links_len(), 1);
        assert_eq!(chain.blocks_len(), 2);
        assert_eq!(chain.len(), 3);
        chain.prune();
        assert_eq!(chain.len(), 3);
        assert_eq!(chain.valid_len(), 3);
        assert!(chain.add_node_block(id1.clone()).is_none());
        assert_eq!(chain.len(), 3);
        assert_eq!(chain.valid_len(), 3);
        chain.remove(id1.identifier());
        assert_eq!(chain.len(), 2);
        assert!(chain.add_node_block(id1.clone()).is_none());
        assert_eq!(chain.len(), 3);
        assert_eq!(chain.valid_len(), 2);
        assert!(chain.write().is_err());
    }

    #[test]
    fn file_based_chain() {
        ::rust_sodium::init();
        let keys = (0..50)
            .map(|_| crypto::sign::gen_keypair())
            .collect_vec();
        // ########################################################################################
        // create groups of keys to resemble close_groups
        // ########################################################################################
        let pub1 = keys.iter().map(|x| x.0).take(3).collect_vec();
        let pub2 = keys.iter().map(|x| x.0).skip(1).take(3).collect_vec();
        let pub3 = keys.iter().map(|x| x.0).skip(2).take(3).collect_vec();
        let link_desc1 = node_block::create_link_descriptor(&pub1[..]).unwrap();
        let identifier1 = BlockIdentifier::Link(link_desc1);
        let id_ident = BlockIdentifier::ImmutableData(hash(b"id1hash"));
        let sd1_ident = BlockIdentifier::StructuredData(hash(b"sd1hash"), hash(b"sd1name"), false);
        let link1_1 = NodeBlock::new(&keys[0].0, &keys[0].1, identifier1.clone());
        let link1_2 = NodeBlock::new(&keys[1].0, &keys[1].1, identifier1.clone());
        let link1_3 = NodeBlock::new(&keys[2].0, &keys[2].1, identifier1);
        let sd1_1 = NodeBlock::new(&keys[1].0, &keys[1].1, sd1_ident.clone());
        let sd1_2 = NodeBlock::new(&keys[2].0, &keys[2].1, sd1_ident.clone());
        let sd1_3 = NodeBlock::new(&keys[3].0, &keys[3].1, sd1_ident);
        let id_1 = NodeBlock::new(&keys[2].0, &keys[2].1, id_ident.clone());
        let id_2 = NodeBlock::new(&keys[1].0, &keys[1].1, id_ident.clone()); // fail w/wrong keys
        let id_3 = NodeBlock::new(&keys[4].0, &keys[4].1, id_ident); // fail w/wrong keys
        // #################### Create chain ########################
        if let Ok(dir) = TempDir::new("test_data_chain") {
            if let Ok(mut chain) = DataChain::create_in_path(dir.path().to_path_buf(), 999) {
                assert!(chain.is_empty());
                // ############# start adding link #####################
                assert!(chain.add_node_block(link1_1.unwrap()).is_none());
                assert!(chain.validate_ownership(&pub1));
                assert_eq!(chain.len(), 1);
                assert!(chain.add_node_block(link1_2.unwrap()).is_some());
                assert!(chain.validate_ownership(&pub1));
                assert_eq!(chain.len(), 1);
                assert!(chain.add_node_block(link1_3.unwrap()).is_some());
                assert!(chain.validate_ownership(&pub1)); // 1 link - all OK
                assert_eq!(chain.len(), 1);
                // ###############################################################################
                // pune_and_validate will prune any invalid data, In first link all data is valid
                // ##############################################################################
                assert!(chain.validate_ownership(&pub1));
                assert!(!chain.validate_ownership(&pub3));
                assert_eq!(chain.len(), 1);
                assert_eq!(chain.blocks_len(), 0);
                assert_eq!(chain.links_len(), 1);
                assert!(chain.add_node_block(sd1_1.unwrap()).is_none());
                assert!(chain.add_node_block(sd1_2.unwrap()).is_some());
                assert_eq!(chain.len(), 2);
                assert_eq!(chain.valid_len(), 2);
                assert!(chain.validate_ownership(&pub2)); // Ok as now 2 is in majority
                assert_eq!(chain.links_len(), 1);
                assert_eq!(chain.blocks_len(), 1);
                assert_eq!(chain.len(), 2);
                assert!(chain.add_node_block(sd1_3.unwrap()).is_some());
                assert!(chain.validate_ownership(&pub2));
                assert_eq!(chain.links_len(), 1);
                assert_eq!(chain.blocks_len(), 1);
                assert_eq!(chain.len(), 2);
                let id1 = id_1.unwrap();
                assert!(chain.add_node_block(id1.clone()).is_none()); // only 1st is valid signature
                assert!(chain.add_node_block(id_2.unwrap()).is_some()); // will not get majority
                assert!(chain.add_node_block(id_3.unwrap()).is_some());
                assert_eq!(chain.links_len(), 1);
                assert_eq!(chain.blocks_len(), 2);
                assert_eq!(chain.len(), 3);
                chain.prune();
                assert_eq!(chain.len(), 3);
                assert_eq!(chain.valid_len(), 3);
                assert!(chain.add_node_block(id1.clone()).is_none());
                assert_eq!(chain.len(), 3);
                assert_eq!(chain.valid_len(), 3);
                chain.remove(id1.identifier());
                assert_eq!(chain.len(), 2);
                assert!(chain.add_node_block(id1.clone()).is_none());
                assert_eq!(chain.len(), 3);
                assert_eq!(chain.valid_len(), 2);
                assert!(chain.write().is_ok());
                let chain2 = DataChain::from_path(dir.path().to_path_buf(), 999);
                assert!(chain2.is_ok());
                assert_eq!(chain2.unwrap(), chain);
            }
        }
    }
}
