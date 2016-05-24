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

use sodiumoxide::crypto::hash::sha256::Digest;
use sodiumoxide::crypto::hash::sha256;
use sodiumoxide::crypto::sign::PublicKey;
use maidsafe_utilities::serialisation;

use error::Error;

/// Dummy data identifiers for this crate
#[allow(missing_docs)]
#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug, Clone)]
pub enum BlockIdentifier {
    Type1(u64),
    Type2(u64),
    /// This digest represents **this nodes** current close group
    /// This is unique to this node, but known by all nodes connected to it
    /// in this group.
    Link(Digest), // hash of group (all current close group id's)
}

impl BlockIdentifier {
    /// Define a name getter as data identifiers may contain more info that does
    /// not change the name (such as with structured data and versions etc.)
    /// In this module we do not care about other info and any validation is outwith this area
    /// Therefore we will delete before insert etc. based on name alone of the data element
    pub fn name(&self) -> Option<u64> {
        match *self {
            BlockIdentifier::Type1(name) => Some(name),
            BlockIdentifier::Type2(name) => Some(name),
            BlockIdentifier::Link(_) => None, // links do not have names
        }
    }

    /// Create a new chain link
    /// All group members should do this on each churn event
    /// All group members should also agree on the exact same members
    /// In a kademlia network then the kademlia invariant should enforce this group agreement.
    pub fn new_link(&mut self, group_ids: &mut [PublicKey]) -> Result<BlockIdentifier, Error> {
        let sorted = group_ids.sort();
        let serialised = try!(serialisation::serialise(&sorted));
        Ok(BlockIdentifier::Link(sha256::hash(&serialised)))
    }
}
