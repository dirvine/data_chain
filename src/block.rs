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

use block_identifier::BlockIdentifier;
use proof::Proof;

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
    pub fn new_block(data_id: BlockIdentifier) -> Block {
        Block {
            identifier: data_id,
            proof: Proof::Block([None; ::GROUP_SIZE]),
        }

    }
    /// construct a link (requires group members signing keys are known)
    pub fn new_link(data_id: BlockIdentifier, group_keys: &mut Vec<PublicKey>) -> Block {
        group_keys.sort();
        // FIXME
        let sorted_proof = group_keys.iter()
            .map(|x| (x.clone(), None))
            .collect();

        Block {
            identifier: data_id,
            proof: Proof::Link(sorted_proof),
        }

    }

    /// is this a link
    pub fn is_link(&self) -> bool {
        match self.proof {
            Proof::Link(_) => true,
            Proof::Block(_) => false,
        }
    }

    /// access proof
    pub fn proof(&self) -> &Proof {
        &self.proof
    }

    /// name of block is name of identifier
    pub fn name(&self) -> Option<u64> {
        self.identifier.name()
    }

    /// Get the identifier
    pub fn identifier(&self) -> &BlockIdentifier {
        &self.identifier
    }
}
