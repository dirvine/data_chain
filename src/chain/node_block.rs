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

use chain::block_identifier::{BlockIdentifier, LinkDescriptor};
use error::Error;
use itertools::Itertools;
use maidsafe_utilities::serialisation;
use rust_sodium::crypto::sign::{self, PublicKey, SecretKey, Signature};
use tiny_keccak::Keccak;

/// Returns a link descriptor with the hash of the group members, or `None` if `group` is empty.
pub fn create_link_descriptor(group: &[PublicKey]) -> Option<LinkDescriptor> {
    if group.is_empty() {
        None
    } else {
        let mut sha3 = Keccak::new_sha3_256();
        for key_bytes in group.iter().map(|key| &key.0).sorted() {
            sha3.update(key_bytes);
        }
        let mut res = [0u8; 32];
        sha3.finalize(&mut res);
        Some(res)
    }
}

/// Proof as provided by a close group member
#[derive(RustcEncodable, RustcDecodable, PartialOrd, Ord, PartialEq, Eq, Debug, Clone)]
pub struct Proof {
    key: PublicKey,
    sig: Signature,
}

impl Proof {
    /// cstr
    pub fn new(key: PublicKey, sig: Signature) -> Proof {
        Proof {
            key: key,
            sig: sig,
        }
    }

    /// getter
    pub fn key(&self) -> &PublicKey {
        &self.key
    }

    /// getter
    pub fn sig(&self) -> &Signature {
        &self.sig
    }
}

/// If data block then this is sent by any group member when data is `Put`, `Post` or `Delete`.
/// If this is a link then it is sent with a `churn` event.
/// A `Link` is a nodeblock that each member must send each other in times of churn.
/// These will not accumulate but be `ManagedNode`  to `ManagedNode` messages in the routing layer
#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug, Clone)]
pub struct NodeBlock {
    identifier: BlockIdentifier,
    proof: Proof,
}

impl NodeBlock {
    /// Create a Block (used by nodes in network to send to holders of `DataChains`)
    pub fn new(pub_key: &PublicKey,
               secret_key: &SecretKey,
               data_identifier: BlockIdentifier)
               -> Result<NodeBlock, Error> {
        let signature = sign::sign_detached(&try!(serialisation::serialise(&data_identifier))[..],
                                            secret_key);
        Ok(NodeBlock {
            identifier: data_identifier,
            proof: Proof::new(*pub_key, signature),
        })
    }

    /// Getter
    pub fn identifier(&self) -> &BlockIdentifier {
        &self.identifier
    }
    /// Getter
    pub fn proof(&self) -> &Proof {
        &self.proof
    }

    /// validate signed correctly
    pub fn validate(&self) -> bool {
        self.validate_detached(&self.identifier)
    }

    /// validate signed correctly
    pub fn validate_detached(&self, identifier: &BlockIdentifier) -> bool {
        match serialisation::serialise(identifier) {
            Ok(data) => sign::verify_detached(self.proof.sig(), &data[..], self.proof.key()),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use chain::block_identifier::BlockIdentifier;
    use rust_sodium::crypto::sign;
    use sha3::hash;
    use super::*;

    #[test]
    fn node_block_comparisons() {
        ::rust_sodium::init();
        let keys = sign::gen_keypair();
        let test_data1 = BlockIdentifier::Link(hash(b"1"));
        let test_data2 = BlockIdentifier::Link(hash(b"1"));
        let test_data3 = BlockIdentifier::ImmutableData(hash(b"1"));
        let test_node_data_block1 = NodeBlock::new(&keys.0, &keys.1, test_data1).expect("fail1");
        let test_node_data_block2 = NodeBlock::new(&keys.0, &keys.1, test_data2).expect("fail2");
        let test_node_data_block3 = NodeBlock::new(&keys.0, &keys.1, test_data3).expect("fail3");
        assert!(test_node_data_block1.validate());
        assert!(test_node_data_block2.validate());
        assert!(test_node_data_block3.validate());
        assert_eq!(test_node_data_block1.clone(), test_node_data_block2.clone());
        assert!(test_node_data_block1 != test_node_data_block3.clone());
        assert!(test_node_data_block2 != test_node_data_block3);
    }
}
