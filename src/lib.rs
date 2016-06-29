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

//! #data_chain
//! Data blocks can be chained to provide verifiable assuredness that they contain network valid
//! data and not injected.
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
//! Please also see [github repository][1],
//! and
//! [RFC][3]
//!
//! # Examples
//!
//! Basic usage:
//!
//! ```rust
//!
//!    extern crate sodiumoxide;
//!    extern crate data_chain;
//!    extern crate itertools;
//!
//!  fn main() {
//!    use sodiumoxide::crypto;
//!    use sodiumoxide::crypto::hash::sha256;
//!    use itertools::Itertools;
//!    use data_chain::{NodeBlock, BlockIdentifier, DataChain, create_link_descriptor};
//!
//!
//! ::sodiumoxide::init();
//! let keys = (0..50)
//!     .map(|_| crypto::sign::gen_keypair())
//!     .collect_vec();
//! // ########################################################################################
//! // create groups of keys to resemble close_groups
//! // ########################################################################################
//! let pub1 = keys.iter().map(|x| x.0).take(3).collect_vec();
//! let pub2 = keys.iter().map(|x| x.0).skip(1).take(3).collect_vec();
//! let pub3 = keys.iter().map(|x| x.0).skip(2).take(3).collect_vec();
//! assert!(pub1 != pub2);
//! assert!(pub1 != pub3);
//! assert!(pub1.len() == 3);
//! assert!(pub2.len() == 3);
//! assert!(pub3.len() == 3);
//! let link_desc1 = create_link_descriptor(&pub1[..]);
//! let identifier1 = BlockIdentifier::Link(link_desc1);
//! let id_ident = BlockIdentifier::ImmutableData(sha256::hash(b"id1hash"));
//! let sd1_ident = BlockIdentifier::StructuredData(sha256::hash(b"sd1hash"),
//!                                                 sha256::hash(b"sd1name"),
//!                                                 false);
//! let sd2_ident = BlockIdentifier::StructuredData(sha256::hash(b"s21hash"),
//!                                                 sha256::hash(b"sd2name"),
//!                                                 true);
//! assert!(identifier1 != id_ident);
//! assert!(identifier1 != sd1_ident);
//! assert!(id_ident != sd1_ident);
//! assert!(sd1_ident != sd2_ident);
//! // ########################################################################################
//! // Create NodeBlocks, these are what nodes send to each other
//! // Here they are all links only. For Put Delete Post
//! // these would be Identifiers for the data types that includes a hash of the serialised data
//! // ########################################################################################
//! let link1_1 = NodeBlock::new(&keys[0].0, &keys[0].1, identifier1.clone());
//! let link1_2 = NodeBlock::new(&keys[1].0, &keys[1].1, identifier1.clone());
//! let link1_3 = NodeBlock::new(&keys[2].0, &keys[2].1, identifier1);
//! let sd1_1 = NodeBlock::new(&keys[1].0, &keys[1].1, sd1_ident.clone());
//! let sd1_2 = NodeBlock::new(&keys[2].0, &keys[2].1, sd1_ident.clone());
//! let sd1_3 = NodeBlock::new(&keys[3].0, &keys[3].1, sd1_ident);
//! let id_1 = NodeBlock::new(&keys[2].0, &keys[2].1, id_ident.clone());
//! let id_2 = NodeBlock::new(&keys[1].0, &keys[1].1, id_ident.clone()); // fail w/wrong keys
//! let id_3 = NodeBlock::new(&keys[4].0, &keys[4].1, id_ident); // fail w/wrong keys
//! // #################### Create chain ########################
//! let mut chain = DataChain::default();
//! assert!(chain.is_empty());
//! // ############# start adding link #####################
//! assert!(chain.add_node_block(link1_1.unwrap()).is_none());
//! assert!(chain.validate_ownership(&pub1));
//! assert_eq!(chain.len(), 1);
//! assert!(chain.add_node_block(link1_2.unwrap()).is_some());
//! assert!(chain.validate_ownership(&pub1));
//! assert_eq!(chain.len(), 1);
//! assert!(chain.add_node_block(link1_3.unwrap()).is_some());
//! assert!(chain.validate_ownership(&pub1)); // 1 link - all OK
//! assert_eq!(chain.len(), 1);
//! // ########################################################################################
//! // pune_and_validate will prune any invalid data, In first link all data is valid if sig OK
//! // ########################################################################################
//! assert!(chain.validate_ownership(&pub1));
//! assert!(!chain.validate_ownership(&pub3));
//! assert_eq!(chain.len(), 1);
//! assert_eq!(chain.blocks_len(), 0);
//! assert_eq!(chain.links_len(), 1);
//! assert!(chain.add_node_block(sd1_1.unwrap()).is_none());
//! assert!(chain.add_node_block(sd1_2.unwrap()).is_some());
//! assert_eq!(chain.len(), 2);
//! assert_eq!(chain.valid_len(), 2);
//! assert!(chain.validate_ownership(&pub2)); // Ok as now 2 is in majority
//! assert_eq!(chain.links_len(), 1);
//! assert_eq!(chain.blocks_len(), 1);
//! assert_eq!(chain.len(), 2);
//! assert!(chain.add_node_block(sd1_3.unwrap()).is_some());
//! assert!(chain.validate_ownership(&pub2));
//! assert_eq!(chain.links_len(), 1);
//! assert_eq!(chain.blocks_len(), 1);
//! assert_eq!(chain.len(), 2);
//! // the call below will not add any links
//! let id1 = id_1.unwrap();
//! assert!(chain.add_node_block(id1.clone()).is_none()); // only 1st id has valid signature
//! assert!(chain.add_node_block(id_2.unwrap()).is_some()); // will not get majority
//! assert!(chain.add_node_block(id_3.unwrap()).is_some());
//! assert_eq!(chain.links_len(), 1);
//! assert_eq!(chain.blocks_len(), 2);
//! assert_eq!(chain.len(), 3);
//! chain.prune();
//! assert_eq!(chain.len(), 3);
//! assert_eq!(chain.valid_len(), 3);
//! assert!(chain.add_node_block(id1.clone()).is_none());
//! assert_eq!(chain.len(), 3);
//! assert_eq!(chain.valid_len(), 3);
//! chain.remove(id1.identifier());
//! assert_eq!(chain.len(), 2);
//! assert!(chain.add_node_block(id1.clone()).is_none());
//! assert_eq!(chain.len(), 3);
//! assert_eq!(chain.valid_len(), 2);
//!
//!  }
//!
//! ```
//!
//! # Panics
//!
//! If index is beyond length of chain
//!
//! [insert()](../data_chain/data_chain/struct.DataChain.html#method.insert)
//!
//! # Errors
//!
//! A chain is usize in length. Passing from 32 -> 64 bit machine may cause an ooverflow error.
//!
//! # Safety
//!
//! There is no use of unsafe blocks, in the DataChain object. There is however unsafe blocks in
//! the memory mapped container.
//!
//! # Aborts
//!
//! There are no aborts in this crate.
//!
//! # Undefined Behaviour
//!
//! None known of.
//! [1]: https://github.com/dirvine/data_chain/tree/master
//! [3]: https://github.com/dirvine/data_chain/blob/master/docs/0029-data-blocks.md

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://dirvine.github.io/data_chain")]

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
#![cfg_attr(feature="clippy", deny(clippy_pedantic))]
#![cfg_attr(feature="clippy", allow(use_debug))]

extern crate sodiumoxide;
extern crate rustc_serialize;
#[macro_use]
extern crate maidsafe_utilities;
extern crate itertools;
// extern crate rayon;

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
pub mod block_identifier;

pub use node_block::{NodeBlock, create_link_descriptor};

pub use block_identifier::BlockIdentifier;

pub use data_chain::DataChain;

