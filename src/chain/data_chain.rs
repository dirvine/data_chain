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

use bincode::rustc_serialize;
use chain::block::Block;
use chain::block_identifier::BlockIdentifier;
use chain::vote::Vote;
use error::Error;
use fs2::FileExt;
use itertools::Itertools;
use maidsafe_utilities::serialisation;
use rust_sodium::crypto::sign::PublicKey;
use std::fmt::{self, Debug, Formatter};
use std::fs;
use std::io::{self, Read, Write};
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
#[derive(Default, PartialEq, RustcEncodable, RustcDecodable)]
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
        let file = fs::OpenOptions::new().read(true).write(true).create_new(true).open(&path)?;
        // hold a lock on the file for the whole session
        file.lock_exclusive()?;
        Ok(DataChain {
            chain: Blocks::default(),
            group_size: group_size,
            path: Some(path),
        })
    }

    /// Open from existing directory
    pub fn from_path(path: PathBuf, group_size: usize) -> Result<DataChain, Error> {
        let path = path.join("data_chain");
        let mut file = fs::OpenOptions::new().read(true).write(true).create(false).open(&path)?;
        // hold a lock on the file for the whole session
        file.lock_exclusive()?;
        let mut buf = Vec::<u8>::new();
        let _ = file.read_to_end(&mut buf)?;
        Ok(DataChain {
            chain: serialisation::deserialise::<Blocks>(&buf[..])?,
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
            let mut file = fs::OpenOptions::new().read(true)
                .write(true)
                .create(false)
                .open(&path.as_path())?;
            return Ok(file.write_all(&serialisation::serialise(&self.chain)?)?);
        }
        Err(Error::NoFile)
    }

    /// Write current data chain to supplied path
    pub fn write_to_new_path(&mut self, path: PathBuf) -> Result<(), Error> {
        let mut file = fs::OpenOptions::new().read(true)
            .write(true)
            .create(false)
            .open(path.as_path())?;
        file.write_all(&serialisation::serialise(&self.chain)?)?;
        self.path = Some(path);
        Ok(file.lock_exclusive()?)
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
        // ensure last good link contains majority of current group
        if let Some(last_link) = self.last_valid_link() {
            return (last_link.proofs()
                .iter()
                .filter(|&k| my_group.iter().any(|&z| PublicKey(z.0) == *k.key()))
                .count() * 2) > last_link.proofs().len();

        } else {
            false
        }
    }

    /// Add a vote received from a peer
    /// Uses  `lazy accumulation`
    /// If vote becomes valid, then it is returned
    pub fn add_vote(&mut self, vote: Vote) -> Option<BlockIdentifier> {
        if !vote.validate() {
            return None;
        }
        let len;
        let links;
        let group_size;
        {
            links = self.valid_links_at_block_id(vote.identifier());
            len = self.chain.len();
            group_size = self.group_size;
            if self.chain.is_empty() {
                if let Ok(mut blk) = Block::new(vote.clone()) {
                    blk.valid = true;
                    info!("vote good (chain start)  - marked block {:?} valid",
                          blk.identifier());
                    self.chain.push(blk.clone());
                    return Some(blk.identifier().clone());
                }
            } else if vote.identifier().is_link() && vote.is_self_vote() {
                return None;
            }
        }
        for blk in &mut self.chain {
            if blk.identifier() == vote.identifier() {
                if blk.proofs().iter().any(|x| x.key() == vote.proof().key()) {
                    info!("duplicate proof");
                    return None;
                }

                blk.add_proof(vote.proof().clone()).unwrap();
                info!("links length {:?}", links.len());
                info!("chain  length {:?}", len);
                if links.len() == 1 ||
                   links.iter()
                    .filter(|x| x.identifier() != vote.identifier())
                    .any(|y| Self::validate_block_with_proof(blk, y, group_size)) {
                    blk.valid = true;
                    info!("vote good  - marked block {:?} valid", blk.identifier());
                    return Some(blk.identifier().clone());
                } else {
                    info!("Vote Ok so block invalid  No quorum for block {:?}",
                          blk.identifier());
                    blk.valid = false;
                    return None;
                }
            }
        }
        if let Ok(ref mut blk) = Block::new(vote) {
            if self.links_len() == 1 {
                blk.valid = true;
            }
            self.chain.push(blk.clone());
            return Some(blk.identifier().clone());
        }
        info!("Could not find any block for this proof");
        None

    }

    /// getter
    pub fn chain(&self) -> &Vec<Block> {
        &self.chain
    }

    // get size of chain for storing on disk
    #[allow(unused)]
    fn size_of(&self) -> u64 {
        rustc_serialize::encoded_size(self)
    }

    /// find a block (user required to test for validity)
    pub fn find(&self, block_identifier: &BlockIdentifier) -> Option<&Block> {
        self.chain.iter().find(|x| x.identifier() == block_identifier)
    }

    /// find block by name from top (only first occurrence)
    pub fn find_name(&self, name: &[u8; 32]) -> Option<&Block> {
        self.chain.iter().rev().find(|x| x.valid && Some(name) == x.identifier().name())
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
                block.valid = true;
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
        self.chain.iter_mut().rev().find(|x| x.identifier().is_link() && x.valid)
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
        if let Some(mut first_link) =
            self.chain
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
    /// FIXME - this needs a complete rewrite
    pub fn merge_chain(&mut self, chain: &mut DataChain) {
        chain.mark_blocks_valid();
        chain.prune();
        let mut start_pos = 0;
        for new in chain.chain().iter().filter(|x| x.identifier().is_block()) {
            let mut insert = false;
            for (pos, val) in self.chain.iter().enumerate().skip(start_pos) {
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
        let p_len = proof.proofs()
            .iter()
            .filter(|&y| block.proofs().iter().any(|p| p.key() == y.key()))
            .count();
        (p_len * 2 >= proof.proofs().len()) || (p_len >= group_size)
    }
}

impl Debug for DataChain {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        let print_block = |block: &Block| -> String {
            let mut output = format!("    Block {{\n        identifier: {:?}\n        valid: {}\n",
                                     block.identifier(),
                                     block.valid);
            for proof in block.proofs() {
                output.push_str(&format!("        {:?}\n", proof))
            }
            output.push_str("    }");
            output
        };
        write!(formatter,
               "DataChain {{\n    group_size: {}\n    path: ",
               self.group_size)?;
        match self.path {
            Some(ref path) => writeln!(formatter, "{}", path.display())?,
            None => writeln!(formatter, "None")?,
        }
        if self.chain.is_empty() {
            write!(formatter, "    chain empty }}")
        } else {
            for block in &self.chain {
                writeln!(formatter, "{}", print_block(block))?
            }
            write!(formatter, "}}")
        }
    }
}

#[cfg(test)]
//#[cfg_attr(rustfmt, rustfmt_skip)]
mod tests {
    extern crate env_logger;
    use super::*;
    use chain::block_identifier::{BlockIdentifier, LinkDescriptor};
    use chain::vote::Vote;
    use itertools::Itertools;
    use rust_sodium::crypto::sign::{self, PublicKey, SecretKey};
    use tempdir::TempDir;

    pub struct Node {
        pub sec_key: SecretKey,
        pub pub_key: PublicKey,
    }

    pub fn node() -> Node {
        let keys = sign::gen_keypair();
        Node {
            sec_key: keys.1,
            pub_key: keys.0,
        }
    }

    #[test]
    fn genesis() {
        let _ = env_logger::init();
        ::rust_sodium::init();
        let nodes = (0..100).map(|_| node()).collect_vec();
        let add_node_1 =
            BlockIdentifier::Link(LinkDescriptor::NodeGained(nodes[1].pub_key.clone()));
        let add_node_2 =
            BlockIdentifier::Link(LinkDescriptor::NodeGained(nodes[2].pub_key.clone()));
        let add_node_3 =
            BlockIdentifier::Link(LinkDescriptor::NodeGained(nodes[3].pub_key.clone()));
        let add_node_4 =
            BlockIdentifier::Link(LinkDescriptor::NodeGained(nodes[4].pub_key.clone()));
        let remove_node_3 =
            BlockIdentifier::Link(LinkDescriptor::NodeLost(nodes[3].pub_key.clone()));

        let mut chain = DataChain::default();
        assert!(chain.is_empty());
        assert!(chain.add_vote(Vote::new(&nodes[1].pub_key, &nodes[1].sec_key, add_node_1)
                        .unwrap())
                    .is_some(),
                "Add first node, should accumulate as valid.");
        assert!(chain.add_vote(Vote::new(&nodes[2].pub_key, &nodes[2].sec_key, add_node_2.clone())
                        .unwrap())
                    .is_none(),
                "Node2 adds link claiming to be from it. Should be none  as this node is not in \
                 chain.");
        assert!(chain.add_vote(Vote::new(&nodes[1].pub_key, &nodes[1].sec_key, add_node_2.clone())
                        .unwrap())
                    .is_some(),
                "This vote should count and validate vote on it's own. Node 2 should not be able \
                 to vote for itself being added.");
        assert!(chain.add_vote(Vote::new(&nodes[2].pub_key, &nodes[2].sec_key, add_node_2)
                        .unwrap())
                    .is_none(),
                "Again check node2 cannot vote for itself.");
        assert!(chain.add_vote(Vote::new(&nodes[2].pub_key, &nodes[2].sec_key, add_node_3.clone())
                        .unwrap())
                    .is_some(),
                "Node2 can vote for next new node, but no quorum");
        assert_eq!(chain.links_len(),
                   2,
                   "quorum should not be met so block invalid");
        assert!(chain.add_vote(Vote::new(&nodes[1].pub_key, &nodes[1].sec_key, add_node_3.clone())
                        .unwrap())
                    .is_some(),
                "Node1 can vote for next new node and match quorum.");
        assert_eq!(chain.links_len(), 3, "quorum should be met so block valid");
        assert!(chain.add_vote(Vote::new(&nodes[3].pub_key, &nodes[3].sec_key, add_node_4.clone())
                .unwrap())
            .is_some());
        assert!(chain.add_vote(Vote::new(&nodes[1].pub_key, &nodes[1].sec_key, add_node_4.clone())
                .unwrap())
            .is_some());
        assert!(chain.add_vote(Vote::new(&nodes[2].pub_key, &nodes[2].sec_key, add_node_4.clone())
                .unwrap())
            .is_some());
        assert_eq!(chain.links_len(), 4, "quorum should be met so block valid");
        // Now we remove a node
        assert!(chain.add_vote(Vote::new(&nodes[3].pub_key,
                                        &nodes[3].sec_key,
                                        remove_node_3.clone())
                        .unwrap())
                    .is_none(),
                "A node cannot remove itself either");
        assert!(chain.add_vote(Vote::new(&nodes[1].pub_key, &nodes[1].sec_key, remove_node_3.clone()).unwrap())
            .is_some());
        assert!(chain.add_vote(Vote::new(&nodes[2].pub_key, &nodes[2].sec_key, remove_node_3.clone()).unwrap())
            .is_some());
        assert_eq!(chain.links_len(), 5, "quorum should be met so block valid");
        info!("{:?}", chain);
    }

    #[test]
    fn network() {
        let nodes = (0..100).map(|_| node()).collect_vec();
        let mut chain = DataChain::default();
        let add_node_1 =
            BlockIdentifier::Link(LinkDescriptor::NodeGained(nodes[1].pub_key.clone()));
        // let add_node_2 =
        //     BlockIdentifier::Link(LinkDescriptor::NodeGained(nodes[2].pub_key.clone()));
        // let add_node_3 =
        //     BlockIdentifier::Link(LinkDescriptor::NodeGained(nodes[3].pub_key.clone()));
        // let add_node_4 =
        //     BlockIdentifier::Link(LinkDescriptor::NodeGained(nodes[4].pub_key.clone()));
        // let remove_node_3 =
        //     BlockIdentifier::Link(LinkDescriptor::NodeLost(nodes[3].pub_key.clone()));
        assert!(chain.add_vote(Vote::new(&nodes[1].pub_key, &nodes[1].sec_key, add_node_1)
                        .unwrap())
                    .is_some(),
                "Add first node, should accumulate as valid.");
    }

    #[test]
    fn file_based_chain() {
        let _ = env_logger::init();
        ::rust_sodium::init();
        info!("creating keys");
        let keys = (0..10)
            .map(|_| sign::gen_keypair())
            .collect_vec();
        let add_node_1 = BlockIdentifier::Link(LinkDescriptor::NodeGained(keys[1].0.clone()));
        let add_node_2 = BlockIdentifier::Link(LinkDescriptor::NodeGained(keys[2].0.clone()));
        let add_node_3 = BlockIdentifier::Link(LinkDescriptor::NodeGained(keys[3].0.clone()));
        let add_node_4 = BlockIdentifier::Link(LinkDescriptor::NodeGained(keys[4].0.clone()));
        // #################### Create chain ########################
        if let Ok(dir) = TempDir::new("test_data_chain") {
            if let Ok(mut chain) = DataChain::create_in_path(dir.path().to_path_buf(), 999) {
                assert!(chain.add_vote(Vote::new(&keys[1].0, &keys[1].1, add_node_1).unwrap())
                    .is_some());
                assert!(chain.add_vote(Vote::new(&keys[1].0, &keys[1].1, add_node_2.clone()).unwrap()).is_some());
                assert!(chain.add_vote(Vote::new(&keys[2].0, &keys[2].1, add_node_3.clone()) .unwrap()).is_some());
                assert!(chain.add_vote(Vote::new(&keys[1].0, &keys[1].1, add_node_3.clone()) .unwrap()).is_some());
                assert!(chain.add_vote(Vote::new(&keys[3].0, &keys[3].1, add_node_4.clone()) .unwrap()).is_some());
                assert!(chain.add_vote(Vote::new(&keys[1].0, &keys[1].1, add_node_4.clone()).unwrap()).is_some());
                assert!(chain.add_vote(Vote::new(&keys[2].0, &keys[2].1, add_node_4.clone()).unwrap()).is_some());
                assert!(chain.write().is_ok());
                let chain2 = DataChain::from_path(dir.path().to_path_buf(), 999);
                assert!(chain2.is_ok());
                assert_eq!(chain2.unwrap(), chain);
            }
        }
    }
}
