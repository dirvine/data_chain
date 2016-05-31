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

use block_identifier::BlockIdentifier;

/// Used to validate chain
/// Block can be a data item or
/// a chain link.
#[allow(missing_docs)]
#[derive(RustcEncodable, RustcDecodable, PartialEq, Clone)]
pub enum Block {
    Link(BlockIdentifier, Vec<(PublicKey, Option<Signature>)>),
    Block(BlockIdentifier, [Option<Signature>; ::GROUP_SIZE]),
}

impl Block {

/// is this a link
pub fn is_link(&self) -> bool {
    match *self {
        Block::Link(_,_) => true,
        Block::Block(_,_) => false,
    }
}

/// is block
pub fn is_block(&self) -> bool {
    !self.is_link()
}

/// getter
pub fn identifier(&self) -> &BlockIdentifier {
    match *self {
        Block::Link(ref id,_) => id,
        Block::Block(ref id,_) => id,
    }
}

/// getter
pub fn link_keys(&self) -> Option<Vec<PublicKey>> {
    match *self {
        Block::Link(_, ref vec) => Some(vec.iter().map(|&x| x.0).collect()),
        Block::Block(_,_) => None,
    }
}

/// getter
pub fn link_vec(&self) -> Option<&Vec<(PublicKey, Option<Signature>)>> {
    match *self {
        Block::Link(_, ref vec) => Some(vec),
        Block::Block(_,_) => None,
    }
}

/// getter
pub fn block_array(&self) -> Option<&[Option<Signature>]> {
    match *self {
        Block::Link(_, _) => None,
        Block::Block(_,ref arr) => Some(arr),
    }
}

}
