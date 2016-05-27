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


use sodiumoxide::crypto::sign::PublicKey;
use sodiumoxide::crypto::hash::sha256::Digest;
use itertools::Itertools;

use block_identifier::BlockIdentifier;
use proof::Proof;
use error::Error;

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
    pub fn new_block(data_id: BlockIdentifier) -> Result<Block, Error> {
        if data_id.is_link() {
            return Err(Error::BadIdentifier);
        }
        Ok(Block {
            identifier: data_id,
            proof: Proof::Block([None; super::GROUP_SIZE]),
        })

    }

    /// construct a link (requires group members signing keys are known)
    pub fn new_link(data_id: BlockIdentifier, group_keys: &Vec<PublicKey>) -> Result<Block, Error> {
        if data_id.is_block() {
            return Err(Error::BadIdentifier);
        }
        let mut sorted_unique_keys = group_keys.iter().unique().collect_vec();
        sorted_unique_keys.sort();
        let sorted_proof = sorted_unique_keys.iter()
            .map(|x| (*x.clone(), None))
            .collect_vec();

        Ok(Block {
            identifier: data_id,
            proof: Proof::Link(sorted_proof),
        })

    }

    /// is this a link
    pub fn is_link(&self) -> bool {
        self.identifier.is_link() && self.proof.link_proof().is_some()
    }

    /// is this a block
    pub fn is_block(&self) -> bool {
        self.identifier.is_block() && self.proof.block_proof().is_some()
    }

    /// access proof
    pub fn proof(&self) -> &Proof {
        &self.proof
    }

    /// name of block is name of identifier
    pub fn hash(&self) -> Digest {
        self.identifier.hash()
    }

    /// Get the identifier
    pub fn identifier(&self) -> &BlockIdentifier {
        &self.identifier
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use block_identifier::BlockIdentifier;
    use sodiumoxide::crypto::hash::sha256;
    use sodiumoxide::crypto;


    #[test]
    fn link_new() {
        ::sodiumoxide::init();
        let mut keys = Vec::new();
        for _ in 0..::GROUP_SIZE {
            keys.push(crypto::sign::gen_keypair().0);
        }
        let data_id = BlockIdentifier::Link(sha256::hash("1".as_bytes()));
        let link = Block::new_link(data_id, &keys);
        assert!(link.is_ok());
        let unwrapped_link = match link {
            Ok(link) => link,
            Err(_) => panic!("not a link"),
        };
        assert!(unwrapped_link.clone().is_link());
        assert!(unwrapped_link.proof().link_proof().is_some());

    }
    #[test]
    fn id_block_new() {
        ::sodiumoxide::init();
        let data_id = BlockIdentifier::ImmutableData(sha256::hash("1".as_bytes()));
        let block = Block::new_block(data_id);
        assert!(block.is_ok());
        let unwrapped_block = match block {
            Ok(block) => block,
            Err(_) => panic!("not a block"),
        };
        assert!(unwrapped_block.clone().is_block());
        assert!(unwrapped_block.proof().block_proof().is_some());
    }
    #[test]
    fn sd_block_new() {
        ::sodiumoxide::init();
        let data_id = BlockIdentifier::StructuredData(sha256::hash("hash".as_bytes()),
                                                      sha256::hash("name".as_bytes()));
        let block = Block::new_block(data_id);
        assert!(block.is_ok());
        let unwrapped_block = match block {
            Ok(block) => block,
            Err(_) => panic!("not a block"),
        };
        assert!(unwrapped_block.clone().is_block());
        assert!(unwrapped_block.proof().block_proof().is_some());
    }
}
