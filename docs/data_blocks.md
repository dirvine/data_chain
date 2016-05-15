# DataChain's

A data structure that may be cryptographically proven to contain valid data that has been secured
onto a decentralised network.

# Abstract

A mechanism to lock data descriptors in a containers that may be held on a decentralised network.
Such structures are cryptographically secured in lock step using a consensus of cryptographic
signatures. These signatures are of a certain size GROUP_SIZE with a QUORUM required to be
considered valid (much like N of P sharing). In a decentralised network that has secured groups,
these signatures are those closest to the holder of a `DataChain`. The `DataChain` will
have a majority of existing group members if it is republished prior to more than
GROUP_SIZE - QUORUM nodes changing. In this situation there is a strong cryptographic proof of the
data validity.

It is though this recondition that assures the ability for a `DataChain` to be validated and
therefore allows data to be republished.


# Motivation

In a fully decentralised network there are many problems to solve, two important issues are:

1. Transferring large amounts of data to replicant nodes on each churn event.

2. Allow data to be republished in a secure manner.

Point 2 actually encompasses two large issues in itself. The ability to start a node and make it's data
available is obviously required where we have large amounts of data to maintain. Another large advantage
is the ability for such a network to recover from a full system outage (full network collapse, worldwide
power outage etc.).

Another very useful "side effect" of data republish is in network upgrades. As long as two versions of
nodes have the ability to accept and store such data then even incompatible upgrades may be an option, that
was not previously possible. This component requires some further research, but would appear to offer a
significant advantage.

# Detailed design


## Data identifier object

A `DataChain` is a chained list of `DataIdentifiers`. A `DataIdentifier` is an object that can uniquely
identify a data item. These identifiers will hold a cryptographic hash of the underlying data item,
but may hold additional information such as name, version etc.

```rust
pub enum DataIdentifier {
    Immutable(sha512),
    Structured(sha512, XorName, u64),
    //         hash    name     version
}

impl DataIdentifier {

pub fn name(&self) -> XorName {
    match *self {
        DataIdentifier::Immutable(hash) => XorName::new(hash),
        DataIdentifier::Structured(_, name, _) => name
    }
}

}

```



## Node data block

As well as `DataIdentifier` each `NodeDataBlock` consists of a  `PublicKey/Signature` pair.
The `PublicKey` can be proven to be the key that signed the `DataIdentifier` using the signature
as the proof.

**NB this assumes the PublicKey is in fact the node name of a node close to the `DataIdentifier`**

```rust

/// Sent by any group member when data is `Put`, `Post` or `Delete` in this group
#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug, Clone)]
pub struct NodeDataBlock {
    identifier: DataIdentifier,
    proof: (PublicKey, Signature),
}

impl NodeDataBlock {
    /// Create a DataBlock (used by nodes in network to send to holders of `DataChains`)
    pub fn new(pub_key: &PublicKey,
               secret_key: &SecretKey,
               data_identifier: DataIdentifier)
               -> Result<NodeDataBlock, Error> {
        let signature =
            crypto::sign::sign_detached(&try!(serialisation::serialise(&data_identifier))[..],
                                        secret_key);

        Ok(NodeDataBlock {
            identifier: data_identifier,
            proof: (pub_key.clone(), signature),
        })

    }
}

```

## Data block

On receipt of a `NodeDataBlock` the receiving node will check first in a cache of `DataBlock`'s
and then in the `DataChain` itself. On finding an entry it add the node to any `DataBlock`. If
no entry is found the receiver will create a new `DataBlock` entry in the cache and await further
notifications from group members of this `DataIdentifier`.



This array must be contain at least QUORUM members and be of CLOSE_GROUP length. It must only contain
nodes close to that data element described by the  `DataIdentifier`.

## Data chain

On accumulation of a majority of signatories the `DataBlock` will be inserted into the `DataCahin`
If it cannot be added (yet) due to lack of a majority consensus then it will remain in the cache
and await further `NodeDataBlock`'s.'

The `DataChain` is validated via a chain of signed elements where there is a majority of signatures
in agreement at each step (lock step). From the first element to the last this chain of majority
signatures will show that the entire chain is valid. This is due to the fact that the current group
will also have a majority of current members in agreement with the last entry.

**To maintain this security, on each churn event the last entry is refreshed to the whole group. This
is added to the chain if it still maintains consensus. If there are several churn events in succession
then there may be several copies of that entry in the chain. This is an unlikely event as data should
constantly be in flux in such a network, but as a safeguard there may be several entries to maintain
integrity of the chain.**

For this reason, duplicate entries are allowed to exist in the chain. In normal circumstances
duplicates will not exist as chains are grown only with successful `Put`, `Post` or `Delete`. These
by their definition cannot be for same data.

A `Delete` event will, however, remove an entry from the chain, but only if the chained consensus
would not be broken. If such a delete did cause a gap in the consensus, effectively breaking the chain
then the entry is maintained and marked as deleted (the actul data is deleted from any disk cache).

The `DataChain` is described below.

```rust

pub struct DataChain {
    chain: Vec<DataBlock>,
    group_size: u64,
}

impl DataChain {
    /// Create a new chain with no elements yet.
    pub fn new(group_size: u64) -> DataChain {
        DataChain {
            chain: Vec::new(),
            group_size: group_size,
        }
    }
    /// Nodes always validate a chain before accepting it
    pub fn validate(&mut self) -> Result<(), Error> {
        if self.chain.is_empty() {
            return Ok(());
        }
        Ok(try!(self.validate_majorities().and(self.validate_signatures())))
    }

    /// Size of close group (maximum proof size)
    pub fn group_size(&self) -> u64 {
        self.group_size
    }

    /// Add a DataBlock to the chain
    pub fn add_block(&mut self, data_block: DataBlock) -> Result<(), Error> {
        let data = try!(serialisation::serialise(&data_block.identifier));

        if let Some(last) = self.chain.last() {
            if !self.has_majority(last, &data_block) {
                return Err(Error::Majority);
            }
        }

        if !data_block.proof
                      .iter()
                      .all(|v| crypto::sign::verify_detached(v.1, &data[..], v.0)) {
            return Err(Error::Signature);
        }
        // TODO Remove any old copies of this data from the chain. It should not happen though
        self.chain.push(data_block);
        Ok(())
    }

    /// number of non-deleted blocks
    pub fn len(&self) -> usize {
        self.chain.iter().filter(|&x| !x.deleted).count()
    }

    /// Contains no blocks that are not deleted
    pub fn empty(&self) -> bool {
        self.len() == 0
    }

    /// Delete a block
    /// Will either remove a block as long as consensus would remain intact
    /// Otherwise mark as deleted.
    /// If block is in front of container (`.fisrt()`) then we delete that.
    pub fn delete(&mut self, name: u64) -> Option<DataBlock> {

        if self.chain.is_empty() {
            return None;
        }

        if name == self.chain[0].identifier().name() {
            return Some(self.chain.remove(0));
        }

        let last_index = self.chain.len();
        if name == self.chain[last_index].identifier().name() {
            // mark as deleted
            self.chain[last_index].mark_deleted();
            return Some(self.chain[last_index].clone());
        }

        if let Ok(index) = self.chain
                               .binary_search_by(|probe| probe.identifier().name().cmp(&name)) {
            if self.has_majority(&self.chain[index + 1], &self.chain[index - 1]) {
                // we can  maintain consensus by removing this iteem
                return Some(self.chain.remove(index));
            } else {
                // mark as deleted
                self.chain[index].mark_deleted();
                return Some(self.chain[index].clone());
            }
        }
        None
    }

    fn validate_majorities(&self) -> Result<(), Error> {
        if self.chain
               .iter()
               .zip(self.chain.iter().skip(1))
               .all(|block| self.has_majority(block.0, block.1)) {
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

    fn has_majority(&self, block0: &DataBlock, block1: &DataBlock) -> bool {
        block1.proof.keys().filter(|k| block0.proof.contains_key(k)).count() as u64 * 2 >
        self.group_size

    }
}

```

## A node can become an archive node if it can prove:

1. The list of data types must contain data types greater than the number currently held by the group
 ( This means each data type ID or SD must outnumber the size currently held by the group)
    -If list of data held is less than provided then these DataBlocks must accumulate as per normal quorum rules
    XXXXXXXXXX Ths is no use as gamers can create off line attacks here XXXXXXXXXXXXXXXX

On node start it will pick up this list after bootstrapping on the network and send it to the group
closest to the previous name of the vault (this is written to the previous data store)

##When the network is growing

The data_block entries must be within the current close group of the claimant node

##When the network has shrunk

The data_block entries are allowed to be outwith the current close_group.

##Struct definition

```rust

struct DataBlock {
    name : XorName,
    list : vec<(DataIdentifier, [8usize; RefreshMsg]>, // current close group refresh mesagges
    claiment_sig_key: crypto::sign::PublicKey,
    claiment_enc_key: crypto::_box::PublicKey,
}

impl DataBlock {
    fn claiment_name()->XorName {
          XorName(self.claiment_sig_key + self.claiment_enc_key)
    }

    fn name() -> XorName {
        sha512(list) xor claiment_name
    }

    fn list() -> &[] {
        list
    }


}

```

On receipt of a Refresh message that contains a DataBlock, the receiving node will confirm each item the list of data names and types (DataIdentifier) are in it's close_group.

##Prevention of injection attacks

To prevent such data being simply created in an off-line attack. To prevent this, the node must have
existed in the network and be able to prove this. This does not completely prevent off-line attacks, but
certainly makes them significantly more difficult and increasingly so as the network grows.

Each Refresh message received from a node is signed by that node to the claimant node. These refresh
messages

In network restarts there exists a window of opportunity for an injection attack. This is a case where
invalid SD in particular could be injected. To prevent this the StructuredData refresh message must
include the hash of the StructuredData element.

####Node memory

Each node id added to the routing table should be "remembered" by all nodes that see this node. These
remembered NodeId's will allow nodes to tie up refresh message node Id's with those found in the
`DataBlock` These "previously seen" nodes should be written to the nodes cache file for later proof.


###Network "difficulty"

The distance of the furthest group member to a nodes own ID is regarded as network difficulty. In small
networks this will wildly fluctuate. This value must be written to the nodes configuration file, in case of SAFE this is the vault configuration file.

###If list of existing data is zero

This is a network restart, therefore we accept these messages as is and confirm there are at least
GROUP_SIZE nodes signed such messages. The difficult measurement must match (or be less than) that of the  current receiving node in the previous network,

###If network difficulty is reduced significantly (less than half previous)

Confirm at least one node in current group exits in the array in the list of that data element.

# Drawbacks

In very small networks (less than approx 3000) network difficulty is a fluctuating number, this can probably not be prevented, but may
allow unwanted data or in fact prevent valid data from being refreshed.


# Alternatives

What other designs have been considered? What is the impact of not doing this?

# Unresolved questions

What parts of the design are still to be done?
