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

//! #data_blocks
//! Data blocks can be chained to provide verifiable assuredness that they contain network valid
//! data and not injected.
//!
//! A chain nay look like
//!
//! ```norun
//! `link` - all current group members - cryptographically secured as valid
//!
//!  data - DataIdentifiers interspersed in a chain of links
//!
//!  data - each block signed by a majority of members of last known link
//!
//!  ....
//!
//! `link` - As churn events occur and groups change new links are created
//!
//! `link` - each link will have a majority (usually n - 1 actually) members of previous link
//! ```
//!
//!  The chain, when presented to the current close_group (the group identified in last link)
//!  can be validated as holding data that has been agreed by the network over time to exist,
//!  A chain provides cryptographic proofs of data and group memberships over time.
//!
//! The link is a group agreement chain component which is created by sorting the closest nodes
//! to a network node (Address) and sending this hash, signed to that node.
//! The recipient will then receive these, `NodeBlocks` and create the chain link.
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

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://dirvine.github.io/data_blocks")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]


#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippyclippy_pedantic))]
#![cfg_attr(feature="clippy", allow(use_debug))]

extern crate sodiumoxide;
extern crate rustc_serialize;
#[macro_use]
extern crate maidsafe_utilities;
// #[cfg(test)]
// extern crate itertools;
// extern crate rayon;

/// Required for consensus agreements. We should work this out though, Magic numbers :-(
pub const GROUP_SIZE: usize = 8;

/// Error types for this crate
pub mod error;

/// A block is a type that contains a `BlockIdentifier` and a `Proof`. These can be data blocks or
/// links
pub mod block;

/// A container of `links` (validated group membership blocks) and normal `blocks` (data elements)
pub mod data_chain;

/// A node block is a partial block, sent by group members to each other to create a `Block`
pub mod node_block;

/// Identify the variant parts of a block, for links this is the Digest of the hash of that group.
mod block_identifier;

/// A container of, either
/// 1. (array) of signed elements for a data item
/// 2. For links a vector of tuples, a `PublicKey` and `Signature` of the `Block`. This is used
///    to identify the corresponding array item in `1.` to verify a signature in a `Block`.
///    Links are self verifying but require the top (fastest) link to contain current group members
///    of any verification group on the network.
mod proof;
