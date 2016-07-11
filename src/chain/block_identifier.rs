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

use sodiumoxide::crypto::hash::sha256::Digest;

/// structured Data name
pub type SdName = Digest;

/// Ledger type (delete or keep)
pub type Ledger = bool;
/// Represents the xored close group for the new group on churn etc.
/// This is signed by each group member.
pub type LinkDescriptor = [u8; 32];


/// Dummy data identifiers for this crate
#[allow(missing_docs)]
#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug, Clone)]
pub enum BlockIdentifier {
    ///           hash is also name of data stored locally
    ImmutableData(Digest),
    ///           hash     name (identity + tag) (stored localy as name in data store)
    StructuredData(Digest, SdName, Ledger),
    /// This array represents **this nodes** current close roup
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
    pub fn hash(&self) -> Digest {
        match *self {
            BlockIdentifier::ImmutableData(hash) => hash,
            BlockIdentifier::StructuredData(hash, _name, _) => hash,
            BlockIdentifier::Link(hash) => Digest(hash),
        }
    }

    /// structured data name != hash of the data or block
    pub fn structured_data_name(&self) -> Option<SdName> {
        match *self {
            BlockIdentifier::ImmutableData(_hash) => None,
            BlockIdentifier::StructuredData(_hash, name, _) => Some(name),
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

    /// Is this a block
    pub fn is_block(&self) -> bool {
        !self.is_link()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sodiumoxide::crypto::hash::sha256;

    #[test]
    fn create_validate_link_identifier() {
        ::sodiumoxide::init();
        let link = BlockIdentifier::Link(sha256::hash(b"1").0);

        assert!(link.is_link());
        assert!(!link.is_block());
        assert!(link.structured_data_name().is_none());
    }

    #[test]
    fn create_validate_immutable_data_identifier() {
        let id_block = BlockIdentifier::ImmutableData(sha256::hash(b"1"));
        assert!(!id_block.is_link());
        assert!(id_block.is_block());
        assert_eq!(id_block.hash(), sha256::hash("1".as_bytes()));
        assert!(id_block.structured_data_name().is_none());
    }

    #[test]
    fn create_validate_structured_data_identifier() {
        let sd_block =
            BlockIdentifier::StructuredData(sha256::hash(b"hash"), sha256::hash(b"name"), false);

        assert!(!sd_block.is_link());
        assert!(sd_block.is_block());
        assert_eq!(sd_block.hash(), sha256::hash("hash".as_bytes()));
        assert!(sd_block.structured_data_name().is_some());
        assert_eq!(sd_block.structured_data_name().expect("sd name"),
                   sha256::hash("name".as_bytes()))
    }

}
