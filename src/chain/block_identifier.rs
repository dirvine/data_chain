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

/// structured Data name
pub type SdName = [u8; 32];

/// Ledger type (delete or keep)
pub type Ledger = bool;
/// Represents the xored close group for the new group on churn etc.
/// This is signed by each group member.
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
    StructuredData([u8; 32], SdName, Ledger),
    /// This array represents **this nodes** current close group
    /// The array is all nodes xored together
    /// This is unique to this node, but known by all nodes connected to it
    /// in this group.
    Link(LinkDescriptor), // hash of group (all current close group id's)
}

impl BlockIdentifier {
    /// Define a name getter as data identifiers may contain more info that does
    /// not change the name (such as with structured data and versions etc.)
    /// In this module we do not care about other info and any validation is outwith this area
    /// Therefore we will delete before insert etc. based on name alone of the data element
    pub fn hash(&self) -> &[u8; 32] {
        match *self {
            BlockIdentifier::StructuredData(ref hash, _name, _) => hash,
            BlockIdentifier::ImmutableData(ref hash) |
            BlockIdentifier::Link(ref hash) => hash,
        }
    }

    /// Is this an identifier with ledger bit set
    pub fn is_ledger(&self) -> bool {
        match *self {
            BlockIdentifier::StructuredData(_hash, _name, ledger) => ledger,
            _ => false,
        }
    }

    /// structured data name != hash of the data or block
    pub fn name(&self) -> Option<&[u8; 32]> {
        match *self {
            BlockIdentifier::ImmutableData(ref hash) => Some(hash),
            BlockIdentifier::StructuredData(_hash, ref name, _) => Some(name),
            BlockIdentifier::Link(_hash) => None,
        }
    }

    /// Is this a link
    pub fn is_link(&self) -> bool {
        match *self {
            BlockIdentifier::ImmutableData(_) |
            BlockIdentifier::StructuredData(_, _, _) => false,
            BlockIdentifier::Link(_) => true,
        }
    }

    /// Is this a data block
    pub fn is_block(&self) -> bool {
        !self.is_link()
    }
}

impl Debug for BlockIdentifier {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        match *self {
            BlockIdentifier::ImmutableData(ref hash) => {
                write!(formatter, "ImmutableData({})", debug_bytes(hash))
            }
            BlockIdentifier::StructuredData(ref hash, ref name, ref ledger) => {
                write!(formatter,
                       "StructuredData(hash: {}, name: {}, ledger: {})",
                       debug_bytes(hash),
                       debug_bytes(name),
                       ledger)
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
        let sd_block = BlockIdentifier::StructuredData(hash(b"hash"), hash(b"name"), false);

        assert!(!sd_block.is_link());
        assert!(sd_block.is_block());
        assert_eq!(*sd_block.hash(), hash(b"hash"));
        assert!(sd_block.name().is_some());
        assert_eq!(*sd_block.name().expect("sd name"), hash(b"name"))
    }
}
