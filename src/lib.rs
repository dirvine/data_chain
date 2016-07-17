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
//! in a chain. There also exists the mechnism o persist these chains over sessions along with
//! a copy of the data itself (the `ChunkStore`). The data representation is via the `Data` module.
//!
//! # Example
//!
//! Basic usage
//!
//! TBD
//!
//! [Github repository](https://github.com/dirvine/data_chain)



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
#![cfg_attr(feature="clippy", deny(clippy))]
#![cfg_attr(feature="clippy", allow(use_debug))]

extern crate sodiumoxide;
extern crate rustc_serialize;
#[macro_use]
extern crate maidsafe_utilities;
extern crate itertools;
extern crate fs2;

#[cfg(test)]
extern crate tempdir;
#[cfg(test)]
#[macro_use]
extern crate unwrap;
#[cfg(test)]
extern crate rand;

/// Error types for this crate
pub mod error;

/// A block is a type that contains a `BlockIdentifier` and a `Proof`. These can be data blocks or
/// links
pub mod chain;

/// Data types
pub mod data;

/// API
pub mod secured_data;
/// Persistant store on disk of Keys and large values
/// TODO should not be public
pub mod chunk_store;

pub use chain::{BlockIdentifier, DataChain, NodeBlock, Proof, create_link_descriptor};

pub use data::{Data, DataIdentifier, ImmutableData, MAX_BYTES, PlainData, StructuredData};
