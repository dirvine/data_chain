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
//! Data blocks can be chained to provide verifiable assuredness that they contain network valid i
//! data and not injected.
//!
//! This crate assumes these objects below are relevent to `close_groups` this allows inegrity
//! check of the `DataChain` in so far as it will hold valid data identifiers agreed by this agroup
//! All groups since the group/network started.
//!
//! These chains allow nodes to become `archive nodes` on a network and also ensure data intergrity
//! AS LONG AS the data identifiers hold a validating element such as hash of the data itself.
//!
//! Another purpose of these chanis is to allow network restarts with valid data. Obviously this
//! means the network nodes will have to tr and restart as the last known ID they had. Vaults
//! will require to accept or reject such nodes in normal operation. On network restart though
//! these nodes may be allowed to join a group if they can present a `DataChain` that appears
//! healthy, even if there is not yet enough consensus to `trust` the data iself just yet.
//! additional nodes will also join this group and hopefully confirm the data integrity is agreed
//! as the last `DataBlock` should contain a majorit of existing group memebers that have signed.
//!
//! Nodes do no require to become `Archive nodes` if they have limied bandwidth or disk space, but
//! they are still valuable as transient nodes which may deliver data stored whle they are in the
//! group. Such nodes may only be involved in consensus and routing stability messages, returning
//! a `Nack` to any `Get` request  due to upstream bandwidth limitations.

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "http://maidsafe.net/img/favicon.ico",
       html_root_url = "http://maidsafe.github.io/crust/")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.
// com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
// FIXME uncomment below
// #![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
//           unknown_crate_types, warnings)]
#![allow(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features,
        unconditional_recursion, unknown_lints, unsafe_code, unused, unused_allocation,
        unused_attributes, unused_comparisons, unused_features, unused_parens, while_true)]
// FIXME below should be warn
#![allow(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippyclippy_pedantic))]
#![cfg_attr(feature="clippy", allow(use_debug))]

extern crate sodiumoxide;
extern crate rustc_serialize;
// extern crate xor_name;
#[macro_use]
extern crate quick_error;
#[macro_use]
extern crate maidsafe_utilities;
extern crate itertools;


use std::collections::HashMap;
use sodiumoxide::crypto;
use sodiumoxide::crypto::sign::{Signature, PublicKey, SecretKey};
// use xor_name::XorName;
use itertools::Itertools;
use maidsafe_utilities::serialisation;

quick_error! {
    /// Crust's universal error type.
    #[derive(Debug)]
    pub enum Error {
   #[allow(missing_docs)]
     Validation{
            description("Failed to validate chain")
            display("Data chain error")
        }
   #[allow(missing_docs)]
     Signature {
            description("Signature failure")
            display("Data not signed by given key")
        }
   #[allow(missing_docs)]
     Majority {
            description("Failed to validate chain")
            display("Data chain majority error")
        }
/// Wrapper for a `maidsafe_utilities::serialisation::SerialisationError`
        SerialisationError(err: serialisation::SerialisationError) {
			            description("Serialisation error")
						display("Serialisation error: {}", err)
						cause(err)
					    from()
	    }
}
}

// dummy data identifiers for this crate
#[derive(RustcEncodable, RustcDecodable)]
pub enum DataIdentifier {
    Type1(u64),
    Type2(u64),
}

/// Sent by any group member when data is `Put`, `Post` or `Delete` in this group
#[derive(RustcEncodable, RustcDecodable)]
pub struct NodeDataBlock {
    identifier: DataIdentifier,
    proof: (PublicKey, Signature),
}

impl NodeDataBlock {
    pub fn new(&mut self,
               pub_key: &PublicKey,
               secret_key: &SecretKey,
               data_identifier: DataIdentifier)
               -> Result<NodeDataBlock, Error> {
        let signature =
            crypto::sign::sign_detached(&try!(serialisation::serialise(&self.identifier))[..],
                                        secret_key);

        Ok(NodeDataBlock {
            identifier: data_identifier,
            proof: (pub_key.clone(), signature),
        })

    }
}

/// used to validate chain `linksi`.
#[derive(RustcEncodable, RustcDecodable)]
pub struct DataBlock {
    identifier: DataIdentifier,
    proof: HashMap<PublicKey, Signature>,
    received_order: u64,
}


/// Created by holder of chain, can be passed to others as proof of data held.
/// This object is verifyable if :
/// The last validation constains the majority of current close group
/// OR on network restart the nodes all must try and restart on
/// previous names. They can continue any validation of the holder of a chain.
/// This requires nodes to always restart as last ID and if there was no restart they are rejected
/// at vault level.
/// If there was a restart then the nodes should validate and continue.
/// N:B this means all nodes can use a named directory for data_store and clear if they restart
/// as a new id. This allows cleanup of old data_cache directories.
#[derive(RustcEncodable, RustcDecodable)]
pub struct DataChain {
    chain: Vec<DataBlock>,
}

impl DataChain {
    pub fn validate(&self) -> Result<(), Error> {
        Ok(())
    }

    fn validate_majorities(&self) -> Result<(), Error> {
        if self.chain
               .iter()
               .zip(self.chain.iter().skip(1))
               .all(|block| has_majority(block.0, block.1)) {
            Ok(())
        } else {
            Err(Error::Majority)
        }
    }

    fn validate_signatures(&self) -> Result<(), Error> {
        if self.chain
               .iter()
               .all(|x| {
                   if let Ok(data) = serialisation::serialise(&x.identifier) {
                       x.proof
                        .iter()
                        .all(|v| crypto::sign::verify_detached(v.1, &data[..], v.0))
                   } else {
                       false
                   }
               }) {
            Ok(())
        } else {
            Err(Error::Signature)
        }

    }
}

fn has_majority(block0: &DataBlock, block1: &DataBlock) -> bool {
    block1.proof.keys().filter(|k| block0.proof.contains_key(k)).count() * 2 > block0.proof.len()
}


#[cfg(test)]
use super::*;
use crypto::sign::SecretKey;
mod tests {
    #[test]
    fn it_works() {}
}
