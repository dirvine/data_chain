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

//! #data_chain
//! Data blocks can be chained to provide verifiable assuredness that they contain network valid
//! data and that the data has been validly put onto the network by a previous consensus. This
//! consensus is validated from the data chain itslf through analysis of the chain links.
//!
//! A chain may look like
//!
//! ```norun
//! `link` - all current group members - cryptographically secured as valid
//!
//!  data - DataIdentifiers interspersed in a chain of links
//!
//!  data - each block signed by a majority of previous link
//!
//!  ....
//!
//! `link` - As churn events occur new links are created
//!
//! `link` - each link will have a majority
//!          (usually n - 1 actually) members of previous link
//! ```
//!
//!  The chain, when presented to the current close group (the group identified in last link)
//!  can be validated as holding data that has been agreed by the network over time to exist,
//!  A chain provides cryptographic proofs of data and group memberships over time.
//!
//! The link is a group agreement chain component which is created by sorting the closest nodes
//! to a network node (Address) and sending this hash, signed to that node.
//! The recipient will then receive these, `Votes` and create the chain link.
//! This link will allow the agreed members of the group so sign `DataBlocks` for the chain
//! If a majority of the link members sign the data, it is validly in the chain.
//! On group membership changes, a new link is constructed in the chain and the process repeats.
//! A chain can split and nodes will maintain several chains, dependent on data overlaps with
//! the chains links.
//! The link identifier is the hash of all group members that contains the current node.
//!
//! Containers of Chain Links only may also be maintained in groups to prove historic memberships
//! of a network. It is not well enough understoof the validity of this action, but it may prove
//! valuable in the event of network restarts.
//! Please also see [RFC][1]
//!
//!
//! [1]: https://github.com/dirvine/data_chain/blob/master/docs/0029-data-blocks.md

/// A block is a type that contains a `BlockIdentifier` and a `Proof`. These can be data blocks or
/// links
mod block;

/// A container of `links` (validated group membership blocks) and normal `blocks` (data elements)
pub mod data_chain;

/// A node block is a partial block, sent by group members to each other to create a `Block`
pub mod node_block;

/// Identify the variant parts of a block, for links this is the Digest of the hash of that group.
mod block_identifier;

pub use chain::block::Block;
pub use chain::block_identifier::BlockIdentifier;
pub use chain::data_chain::DataChain;
pub use chain::node_block::{Proof, Vote, create_link_descriptor};
use std::fmt::Write;

fn debug_bytes<V: AsRef<[u8]>>(input: V) -> String {
    let input_ref = input.as_ref();
    if input_ref.is_empty() {
        return "<empty>".to_owned();
    }
    if input_ref.len() <= 6 {
        let mut ret = String::new();
        for byte in input_ref.iter() {
            write!(ret, "{:02x}", byte).unwrap_or(());
        }
        return ret;
    }
    format!("{:02x}{:02x}{:02x}..{:02x}{:02x}{:02x}",
            input_ref[0],
            input_ref[1],
            input_ref[2],
            input_ref[input_ref.len() - 3],
            input_ref[input_ref.len() - 2],
            input_ref[input_ref.len() - 1])
}
