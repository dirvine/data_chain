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


use sodiumoxide::crypto;
use maidsafe_utilities::serialisation;
use block_identifier::BlockIdentifier;
use node_block::{NodeBlock, Proof};
use error::Error;

/// Used to validate chain
/// Block can be a data item or
/// a chain link.
#[allow(missing_docs)]
#[derive(Debug, RustcEncodable, RustcDecodable, PartialEq, Clone)]
pub struct Block {
    identifier: BlockIdentifier,
    proof: Vec<Proof>,
    pub valid: bool,
}

impl Block {
    /// new block
    pub fn new(node_block: NodeBlock) -> Result<Block, Error> {
        if !node_block.validate() {
            return Err(Error::Signature);
        }
        let mut vec = Vec::new();
        vec.push(Proof::new(*node_block.proof().key(), *node_block.proof().sig()));
        Ok(Block {
            identifier: node_block.identifier().clone(),
            proof: vec,
            valid: false,
        })
    }

    /// Add a proof from a peer
    pub fn add_proof(&mut self, proof: Proof) -> Result<(), Error> {
        if !self.validate_proof(&proof) {
            return Err(Error::Signature);
        }
        if !self.proof().iter().any(|x| x.key() == proof.key()) {
            self.proof.push(Proof::new(*proof.key(), *proof.sig()));
            return Ok(());
        }
        Err(Error::Validation)
    }

    /// validate signed correctly
    pub fn validate_proof(&self, proof: &Proof) -> bool {
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
        self.proof().iter().all(|x| crypto::sign::verify_detached(x.sig(), &data[..], x.key()))
    }

    /// Prune any bad signatures.
    pub fn remove_invalid_signatures(&mut self) {
        let data = if let Ok(data) = serialisation::serialise(&self.identifier) {
            data
        } else {
            self.proof.clear();
            return;
        };
        self.proof.retain(|x| crypto::sign::verify_detached(x.sig(), &data[..], x.key()));
    }

    /// getter
    pub fn proof(&self) -> &Vec<Proof> {
        &self.proof
    }

    /// getter
    pub fn proof_mut(&mut self) -> &Vec<Proof> {
        &self.proof
    }

    /// getter
    pub fn identifier(&self) -> &BlockIdentifier {
        &self.identifier
    }
}
