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


use sodiumoxide::crypto::sign::{PublicKey, Signature};
use sodiumoxide::crypto;
use maidsafe_utilities::serialisation;
use block_identifier::BlockIdentifier;
use node_block::{NodeBlock, NodeBlockProof};
use error::Error;

/// Used to validate chain
/// Block can be a data item or
/// a chain link.
#[allow(missing_docs)]
#[derive(RustcEncodable, RustcDecodable, PartialEq, Clone)]
pub struct Block {
    identifier: BlockIdentifier,
    proof: Vec<(PublicKey, Signature)>,
    pub valid: bool,
}

impl Block {
    /// new block
    pub fn new(node_block: NodeBlock) -> Result<Block, Error> {
        if !node_block.validate() {
            return Err(Error::Signature);
        }
        let mut vec = Vec::new();
        vec.push((*node_block.proof().key(), *node_block.proof().sig()));
        Ok(Block {
            identifier: node_block.identifier().clone(),
            proof: vec,
            valid: false,
        })
    }

    /// Add a proof from a peer
    pub fn add_proof(&mut self, proof: NodeBlockProof) -> Result<(), Error> {
        if !self.validate_proof(&proof) {
            return Err(Error::Signature);
        }
        self.proof.push((*proof.key(), *proof.sig()));
        self.proof.sort();
        self.proof.dedup();
        Ok(())
    }

    /// validate signed correctly
    pub fn validate_proof(&self, proof: &NodeBlockProof) -> bool {
        let data = if let Ok(data) = serialisation::serialise(&self.identifier) {
            data
        } else {
            return false;
        };
        crypto::sign::verify_detached(proof.sig(), &data[..], proof.key())
    }

    /// validate signed correctly
    pub fn validate_block_signatures(&self) -> bool {
        let data = if let Ok(data) = serialisation::serialise(&self.identifier) {
            data
        } else {
            return false;
        };
        self.proof().iter().all(|x| crypto::sign::verify_detached(&x.1, &data[..], &x.0))
    }

    /// Prune any bad signatures.
    pub fn remove_invalid_signatures(&mut self) {
        let data = if let Ok(data) = serialisation::serialise(&self.identifier) {
            data
        } else {
            self.valid = false;
            return;
        };
        self.proof.retain(|x| !crypto::sign::verify_detached(&x.1, &data[..], &x.0));
    }

    /// getter
    pub fn proof(&self) -> &Vec<(PublicKey, Signature)> {
        &self.proof
    }

    /// getter
    pub fn proof_mut(&mut self) -> &Vec<(PublicKey, Signature)> {
        &self.proof
    }

    /// getter
    pub fn identifier(&self) -> &BlockIdentifier {
        &self.identifier
    }
}
