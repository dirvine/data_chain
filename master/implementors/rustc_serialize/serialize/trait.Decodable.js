(function() {var implementors = {};
implementors["bincode"] = ["impl&lt;T:&nbsp;<a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a>&gt; <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='bincode/struct.RefBox.html' title='bincode::RefBox'>RefBox</a>&lt;'static, T&gt;","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='bincode/struct.StrBox.html' title='bincode::StrBox'>StrBox</a>&lt;'static&gt;","impl&lt;T:&nbsp;<a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a>&gt; <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='bincode/struct.SliceBox.html' title='bincode::SliceBox'>SliceBox</a>&lt;'static, T&gt;",];implementors["maidsafe_utilities"] = ["impl&lt;T&gt; <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='bincode/refbox/struct.RefBox.html' title='bincode::refbox::RefBox'>RefBox</a>&lt;'static, T&gt; <span class='where'>where T: <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a></span>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='bincode/refbox/struct.StrBox.html' title='bincode::refbox::StrBox'>StrBox</a>&lt;'static&gt;","impl&lt;T&gt; <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='bincode/refbox/struct.SliceBox.html' title='bincode::refbox::SliceBox'>SliceBox</a>&lt;'static, T&gt; <span class='where'>where T: <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a></span>",];implementors["rust_sodium"] = ["impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/box_/curve25519xsalsa20poly1305/struct.SecretKey.html' title='rust_sodium::crypto::box_::curve25519xsalsa20poly1305::SecretKey'>SecretKey</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/box_/curve25519xsalsa20poly1305/struct.PublicKey.html' title='rust_sodium::crypto::box_::curve25519xsalsa20poly1305::PublicKey'>PublicKey</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/box_/curve25519xsalsa20poly1305/struct.Nonce.html' title='rust_sodium::crypto::box_::curve25519xsalsa20poly1305::Nonce'>Nonce</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/box_/curve25519xsalsa20poly1305/struct.PrecomputedKey.html' title='rust_sodium::crypto::box_::curve25519xsalsa20poly1305::PrecomputedKey'>PrecomputedKey</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/sign/ed25519/struct.Seed.html' title='rust_sodium::crypto::sign::ed25519::Seed'>Seed</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/sign/ed25519/struct.SecretKey.html' title='rust_sodium::crypto::sign::ed25519::SecretKey'>SecretKey</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/sign/ed25519/struct.PublicKey.html' title='rust_sodium::crypto::sign::ed25519::PublicKey'>PublicKey</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/sign/ed25519/struct.Signature.html' title='rust_sodium::crypto::sign::ed25519::Signature'>Signature</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/scalarmult/curve25519/struct.Scalar.html' title='rust_sodium::crypto::scalarmult::curve25519::Scalar'>Scalar</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/scalarmult/curve25519/struct.GroupElement.html' title='rust_sodium::crypto::scalarmult::curve25519::GroupElement'>GroupElement</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/auth/hmacsha512/struct.Key.html' title='rust_sodium::crypto::auth::hmacsha512::Key'>Key</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/auth/hmacsha512/struct.Tag.html' title='rust_sodium::crypto::auth::hmacsha512::Tag'>Tag</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/auth/hmacsha512256/struct.Key.html' title='rust_sodium::crypto::auth::hmacsha512256::Key'>Key</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/auth/hmacsha512256/struct.Tag.html' title='rust_sodium::crypto::auth::hmacsha512256::Tag'>Tag</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/auth/hmacsha256/struct.Key.html' title='rust_sodium::crypto::auth::hmacsha256::Key'>Key</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/auth/hmacsha256/struct.Tag.html' title='rust_sodium::crypto::auth::hmacsha256::Tag'>Tag</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/hash/sha512/struct.Digest.html' title='rust_sodium::crypto::hash::sha512::Digest'>Digest</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/hash/sha256/struct.Digest.html' title='rust_sodium::crypto::hash::sha256::Digest'>Digest</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/secretbox/xsalsa20poly1305/struct.Key.html' title='rust_sodium::crypto::secretbox::xsalsa20poly1305::Key'>Key</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/secretbox/xsalsa20poly1305/struct.Nonce.html' title='rust_sodium::crypto::secretbox::xsalsa20poly1305::Nonce'>Nonce</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/onetimeauth/poly1305/struct.Key.html' title='rust_sodium::crypto::onetimeauth::poly1305::Key'>Key</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/onetimeauth/poly1305/struct.Tag.html' title='rust_sodium::crypto::onetimeauth::poly1305::Tag'>Tag</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/pwhash/scryptsalsa208sha256/struct.Salt.html' title='rust_sodium::crypto::pwhash::scryptsalsa208sha256::Salt'>Salt</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/pwhash/scryptsalsa208sha256/struct.HashedPassword.html' title='rust_sodium::crypto::pwhash::scryptsalsa208sha256::HashedPassword'>HashedPassword</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/stream/xsalsa20/struct.Key.html' title='rust_sodium::crypto::stream::xsalsa20::Key'>Key</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/stream/xsalsa20/struct.Nonce.html' title='rust_sodium::crypto::stream::xsalsa20::Nonce'>Nonce</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/stream/aes128ctr/struct.Key.html' title='rust_sodium::crypto::stream::aes128ctr::Key'>Key</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/stream/aes128ctr/struct.Nonce.html' title='rust_sodium::crypto::stream::aes128ctr::Nonce'>Nonce</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/stream/salsa208/struct.Key.html' title='rust_sodium::crypto::stream::salsa208::Key'>Key</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/stream/salsa208/struct.Nonce.html' title='rust_sodium::crypto::stream::salsa208::Nonce'>Nonce</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/stream/salsa2012/struct.Key.html' title='rust_sodium::crypto::stream::salsa2012::Key'>Key</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/stream/salsa2012/struct.Nonce.html' title='rust_sodium::crypto::stream::salsa2012::Nonce'>Nonce</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/stream/salsa20/struct.Key.html' title='rust_sodium::crypto::stream::salsa20::Key'>Key</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/stream/salsa20/struct.Nonce.html' title='rust_sodium::crypto::stream::salsa20::Nonce'>Nonce</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/stream/chacha20/struct.Key.html' title='rust_sodium::crypto::stream::chacha20::Key'>Key</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/stream/chacha20/struct.Nonce.html' title='rust_sodium::crypto::stream::chacha20::Nonce'>Nonce</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/shorthash/siphash24/struct.Digest.html' title='rust_sodium::crypto::shorthash::siphash24::Digest'>Digest</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='rust_sodium/crypto/shorthash/siphash24/struct.Key.html' title='rust_sodium::crypto::shorthash::siphash24::Key'>Key</a>",];implementors["data_chain"] = ["impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='data_chain/struct.Block.html' title='data_chain::Block'>Block</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='data_chain/chain/data_chain/struct.DataChain.html' title='data_chain::chain::data_chain::DataChain'>DataChain</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='data_chain/chain/node_block/struct.Proof.html' title='data_chain::chain::node_block::Proof'>Proof</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='data_chain/chain/node_block/struct.NodeBlock.html' title='data_chain::chain::node_block::NodeBlock'>NodeBlock</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='enum' href='data_chain/enum.BlockIdentifier.html' title='data_chain::BlockIdentifier'>BlockIdentifier</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='data_chain/data/immutable_data/struct.ImmutableData.html' title='data_chain::data::immutable_data::ImmutableData'>ImmutableData</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='struct' href='data_chain/data/structured_data/struct.StructuredData.html' title='data_chain::data::structured_data::StructuredData'>StructuredData</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='enum' href='data_chain/data/enum.Data.html' title='data_chain::data::Data'>Data</a>","impl <a class='trait' href='rustc_serialize/serialize/trait.Decodable.html' title='rustc_serialize::serialize::Decodable'>Decodable</a> for <a class='enum' href='data_chain/data/enum.DataIdentifier.html' title='data_chain::data::DataIdentifier'>DataIdentifier</a>",];

            if (window.register_implementors) {
                window.register_implementors(implementors);
            } else {
                window.pending_implementors = implementors;
            }
        
})()
