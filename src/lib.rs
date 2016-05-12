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
            display("Data chain error")
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


#[derive(RustcEncodable, RustcDecodable)]
pub enum DataIdentifier {
    Type1(u64),
    Type2(u64),
}

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


#[derive(RustcEncodable, RustcDecodable)]
pub struct DataBlock {
    identifier: DataIdentifier,
    proof: HashMap<PublicKey, Signature>,
    received_order: u64,
}

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
mod tests {
    #[test]
    fn it_works() {}
}
