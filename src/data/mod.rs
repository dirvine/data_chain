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

//! # Data types
//!
//! These data types fall into three categories
//!
//! - Immutable : This data type has fixed content and self validates. The name is derived from the
//!               hash of the content.
//!
//! - Structured : This is `owned` data and reflects a location in the address space that contains
//!                content that may be altered by the owner(s).
//!
//! - Plain : This is data with no fixed content or name. It is currently unused in SAFE
//!


mod data;

/// Data that will not change it's contents
pub mod immutable_data;
/// Data that will retain it's name but allow dynamic content or transfer of ownership
pub mod structured_data;
/// Flexible and insecure data type with no fixed invarients. The name and content are not related.
pub mod plain_data;

pub use data::data::{Data, DataIdentifier};
pub use data::immutable_data::ImmutableData;
pub use data::plain_data::PlainData;
pub use data::structured_data::{MAX_BYTES, StructuredData};
