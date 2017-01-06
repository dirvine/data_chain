// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1 This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use std::fmt::{self, Debug, Formatter};
use super::debug_bytes;
use data::DataIdentifier;

/// Ledger type (delete or keep)
pub type Ledger = bool;

/// Hash of the public keys of all group members (keys are lexicographically sorted before hashing).
///
/// Each node in the group signs this to form a `Proof`.
pub type LinkDescriptor = [u8; 32];

/// Data identifiers for use in a data Chain.
/// The hash of each data type is available to ensure there is no confusion
/// over the validity of any data presented by this chain
#[allow(missing_docs)]
#[derive(RustcEncodable, RustcDecodable, PartialEq, Clone)]
pub enum BlockIdentifier {
    ///           hash is also name of data stored locally
    ImmutableData([u8; 32]),
    ///           hash     name (identity + tag) (stored localy as name in data store)
    StructuredData([u8; 32], DataIdentifier),
    /// Hash of group members' public keys (see `LinkDescriptor`).
    Link(LinkDescriptor),
}

impl BlockIdentifier {
    /// Define a name getter as data identifiers may contain more info that does
    /// not change the name (such as with structured data and versions etc.)
    /// In this module we do not care about other info and any validation is outwith this area
    /// Therefore we will delete before insert etc. based on name alone of the data element
    pub fn hash(&self) -> &[u8; 32] {
        match *self {
            BlockIdentifier::StructuredData(ref hash, _name) => hash,
            BlockIdentifier::ImmutableData(ref hash) |
            BlockIdentifier::Link(ref hash) => hash,
        }
    }

    /// structured data name != hash of the data or block
    pub fn name(&self) -> Option<&[u8; 32]> {
        match *self {
            BlockIdentifier::ImmutableData(ref hash) => Some(hash),
            BlockIdentifier::StructuredData(_hash, ref id) => Some(id.name()),
            BlockIdentifier::Link(_hash) => None,
        }
    }

    /// Is this a link
    pub fn is_link(&self) -> bool {
        match *self {
            BlockIdentifier::ImmutableData(_) |
            BlockIdentifier::StructuredData(_, _) => false,
            BlockIdentifier::Link(_) => true,
        }
    }

    /// Is this a data block
    pub fn is_block(&self) -> bool {
        match *self {
            BlockIdentifier::ImmutableData(_) |
            BlockIdentifier::StructuredData(_, _) => true,
            BlockIdentifier::Link(_) => false,
        }
    }
}

impl Debug for BlockIdentifier {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            BlockIdentifier::ImmutableData(ref hash) => {
                write!(formatter, "ImmutableData({})", debug_bytes(hash))
            }
            BlockIdentifier::StructuredData(ref hash, ref name) => {
                write!(formatter,
                       "StructuredData(hash: {}, name: {:?})",
                       debug_bytes(hash),
                       name)
            }
            BlockIdentifier::Link(ref descriptor) => {
                write!(formatter, "Link({})", debug_bytes(descriptor))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use sha3::hash;
    use data::DataIdentifier;
    use super::*;

    #[test]
    fn create_validate_link_identifier() {
        ::rust_sodium::init();
        let link = BlockIdentifier::Link(hash(b"1"));

        assert!(link.is_link());
        assert!(!link.is_block());
        assert!(link.name().is_none());
    }

    #[test]
    fn create_validate_immutable_data_identifier() {
        let id_block = BlockIdentifier::ImmutableData(hash(b"1"));
        assert!(!id_block.is_link());
        assert!(id_block.is_block());
        assert_eq!(*id_block.hash(), hash(b"1"));
        assert!(id_block.name().is_some());
    }

    #[test]
    fn create_validate_structured_data_identifier() {
        let sd_block = BlockIdentifier::StructuredData(hash(b"hash"), DataIdentifier::Structured(hash(b"name"), 1));

        assert!(!sd_block.is_link());
        assert!(sd_block.is_block());
        assert_eq!(*sd_block.hash(), hash(b"hash"));
        assert!(sd_block.name().is_some());
        assert_eq!(*sd_block.name().expect("sd name"), hash(b"name"))
    }
}
