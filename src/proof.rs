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

use sodiumoxide::crypto::sign::{Signature, PublicKey};


/// Every block has an attached proof type (group of signatures)
/// Link proofs also contain the public keys allowed to sign data blocks.
/// The link is ordered
/// Block signatures are placed in the appropriate slot of the array
#[allow(missing_docs)]
#[derive(RustcEncodable, RustcDecodable, PartialEq, Clone)]
pub enum Proof {
    Link(Vec<(PublicKey, Option<Signature>)>),
    Block([Option<Signature>; ::GROUP_SIZE]),
}

impl Proof {
    /// link proof
    pub fn link_proof(&self) -> Option<&Vec<(PublicKey, Option<Signature>)>> {
        match *self {
            Proof::Link(ref proof) => Some(&proof),
            _ => None,
        }
    }

    /// link proof
    pub fn block_proof(&self) -> Option<&[Option<Signature>; ::GROUP_SIZE]> {
        match *self {
            Proof::Block(ref proof) => Some(&proof),
            _ => None,
        }
    }
}
