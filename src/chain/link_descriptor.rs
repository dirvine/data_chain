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


use ed25519_dalek::PublicKey;
use serde::{Deserialize, Serialize};

/// What caused group to change?
#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
pub enum LinkDescriptor {
    NodeLost(PublicKey),
    NodeGained(PublicKey),
    Split,
}

impl LinkDescriptor {
    pub fn name(&self) -> Option<&PublicKey> {
        match *self {
            LinkDescriptor::NodeLost(ref h) | LinkDescriptor::NodeGained(ref h) => Some(h),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;

    #[test]
    fn create_validate_link_identifier() {
        let mut csprng = OsRng{};
        let keys = Keypair::generate(&mut csprng);
        let link = LinkDescriptor::NodeGained(keys.public);

        assert!(link.name().is_some());
    }
}
