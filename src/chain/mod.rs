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

/// A block is a type that contains a `BlockIdentifier` and a `Proof`. These can be data blocks or
/// links
mod block;

/// A container of `links` (validated group membership blocks) and normal `blocks` (data elements)
pub mod data_chain;

/// A node block is a partial block, sent by group members to each other to create a `Block`
pub mod node_block;

/// Identify the variant parts of a block, for links this is the Digest of the hash of that group.
mod block_identifier;


pub use chain::node_block::{NodeBlock, create_link_descriptor};
pub use chain::block_identifier::BlockIdentifier;
pub use chain::data_chain::DataChain;