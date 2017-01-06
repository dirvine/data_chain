// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use data::DataIdentifier;
use rustc_serialize::{Decodable, Decoder, Encodable, Encoder};
use sha3::hash;
use std::fmt::{self, Debug, Formatter};

/// An immutable chunk of data.
#[derive(Hash, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct ImmutableData {
    name: [u8; 32],
    value: Vec<u8>,
}

impl ImmutableData {
    /// Creates a new instance of `ImmutableData`
    pub fn new(value: Vec<u8>) -> ImmutableData {
        ImmutableData {
            name: hash(&value),
            value: value,
        }
    }

    /// Returns the value
    pub fn value(&self) -> &Vec<u8> {
        &self.value
    }

    /// Returns name ensuring invariant.
    pub fn name(&self) -> &[u8; 32] {
        &self.name
    }

    /// Returns size of contained value.
    pub fn payload_size(&self) -> usize {
        self.value.len()
    }

    /// Returns `DataIdentifier` for this data element.
    pub fn identifier(&self) -> DataIdentifier {
        DataIdentifier::Immutable(self.name)
    }
}


impl Encodable for ImmutableData {
    fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), E::Error> {
        self.value.encode(encoder)
    }
}

impl Decodable for ImmutableData {
    fn decode<D: Decoder>(decoder: &mut D) -> Result<ImmutableData, D::Error> {
        let value: Vec<u8> = Decodable::decode(decoder)?;
        Ok(ImmutableData {
            name: hash(&value),
            value: value,
        })
    }
}

impl Debug for ImmutableData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "ImmutableData {:?}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use rustc_serialize::hex::ToHex;
    use super::*;

    #[test]
    fn deterministic_test() {
        let value = "immutable data value".to_owned().into_bytes();

        // Normal
        let immutable_data = ImmutableData::new(value);
        let immutable_data_name = immutable_data.name().as_ref().to_hex();
        let expected_name = "fac2869677ee06277633c37ac7e8e5c655f3d652f707c7a79fab930d584a3016";

        assert_eq!(&expected_name, &immutable_data_name);
    }
}
