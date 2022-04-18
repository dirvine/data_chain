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

use crate::chain::block_identifier::LinkDescriptor;
use crate::chain::proof::Proof;
use crate::chain::vote::Vote;
use crate::error::Error;
use rmp_serde::{Deserializer, Serializer};
use serde::{Deserialize, Serialize};

/// Used to validate chain
/// Block can be a data item or
/// a chain link.
#[allow(missing_docs)]
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct Block {
    identifier: LinkDescriptor,
    proofs: Vec<Proof>,
    pub valid: bool,
}

impl Block {
    /// new block
    pub fn new(vote: Vote) -> Result<Block, Error> {
        if !vote.validate() {
            return Err(Error::Signature);
        }
        Ok(Block {
            identifier: vote.identifier().clone(),
            proofs: vec![vote.proof().clone()],
            valid: false,
        })
    }

    /// Add a proof from a peer
    pub fn add_proof(&mut self, proof: Proof) -> Result<(), Error> {
        if !self.validate_proof(&proof) {
            return Err(Error::Signature);
        }
        if !self.proofs.iter().any(|x| x.key() == proof.key()) {
            self.proofs.push(proof);
            return Ok(());
        }
        Err(Error::Validation)
    }

    /// validate signed correctly
    pub fn validate_proof(&self, proof: &Proof) -> bool {
        let mut buf = Vec::new();
        &self.identifier.serialize(&mut Serializer::new(&mut buf));
        proof.validate(&buf[..])
    }

    /// validate signed correctly
    pub fn validate_block_signatures(&self) -> bool {
        let mut buf = Vec::new();
        &self.identifier.serialize(&mut Serializer::new(&mut buf));
        self.proofs.iter().all(|proof| proof.validate(&buf[..]))
    }

    /// Prune any bad signatures.
    pub fn remove_invalid_signatures(&mut self) {
                let mut buf = Vec::new();
        &self.identifier.serialize(&mut Serializer::new(&mut buf));
        self.proofs.retain(|proof| proof.validate(&buf[..]));
    }

    /// getter
    pub fn proofs(&self) -> &Vec<Proof> {
        &self.proofs
    }

    /// getter
    pub fn proofs_mut(&mut self) -> &mut Vec<Proof> {
        &mut self.proofs
    }

    /// getter
    pub fn identifier(&self) -> &LinkDescriptor {
        &self.identifier
    }
}
