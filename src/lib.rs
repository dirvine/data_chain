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

//! # Data Chain
//!
//! This crate holds three modules that together allow nodes in a decentralised network to manage
//! data and history of data and nodes in a container that in itself is decentralised.
//!
//! The modules here include the ability to cryptographically lock history of data and nodes
//! in a chain. There also exists the mechnism to persist these chains over sessions along with
//! a copy of the data itself (the `ChunkStore`). Data representation is via the `Data` module.
//!
//! # Example
//!
//! Basic usage
//!
//! TBD
//!
//! [Github repository](https://github.com/dirvine/data_chain)

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "http://maidsafe.net/img/favicon.ico",
    html_root_url = "http://dirvine.github.io/data_chain"
)]

#[macro_use]
extern crate log;

#[cfg(test)]
extern crate rand;

#[cfg(test)]
#[macro_use]
extern crate unwrap;

/// Error types for this crate
pub mod error;

/// A block is a type that contains a `BlockIdentifier` and a `Proof`. These can be data blocks or
/// links. When enough blocks (`Vote`s) are received from other nodes a block
/// becomes valid. This is a cetnral type to the security of republishable data
/// on the network.
pub mod chain;

pub mod sha3;

pub use chain::{Block, DataChain, LinkDescriptor, Proof, Vote};
