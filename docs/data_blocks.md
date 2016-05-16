# DataChain's

A data structure that may be cryptographically proven to contain valid data that has been secured
onto a decentralised network.

# Definitions used

- Decentralised network, A peer to peer network in xor space, using Kadmelia type addressing.
- hash, a cryptographic one way function that produces a fixed length representation of any input.
- Immutable data, a data type that has a name == hash of it's contents (it is immutable as changing
  the contents creates a new peice of immutable data).
- Structured data, a data type that has a fixed name, but mutable contents.
- GROUP_SIZE, the number of nodes surrounding a network address (Magic number, i.e. selected by
  developer).
- QUORUM, the number of the GROUP that is considered large enough that a decision is valid. In this
  paper this number is considered a majority (i.e. (GROUP_SIZE / 2) + 1)
- Chain consensus, the fact that QUORUM number of signatories exist in the next link (`DataBlock` as
  described below) that also exist in the previous block.

# Abstract

A mechanism to lock data descriptors in containers that may be held on a decentralised network.
Such structures are cryptographically secured in lock step using a consensus of cryptographic
signatures. These signatures are of a certain size GROUP_SIZE with a QUORUM required to be
considered valid (much like N of P sharing). In a decentralised network that has secured groups,
these signatures are those closest to the holder of a `DataChain`. The `DataChain` will have a
majority of existing group members if it is republished prior to more than GROUP_SIZE - QUORUM nodes
changing. In this situation, there is a strong cryptographic proof of the data validity.

When a `DataChain` starts the entries are signed by ever changing majority of pre-existing nodes.
As the chain grows, this rolling majority of different signatories can be cryptographically
confirmed.  This process continues to the very top of the chain which will contain entries signed by
the majority of the current close group of nodes. This current group of nodes can cryptographically
validate the entire chain and every data element referred to within it.

As groups change and the network grows, or indeed shrinks, many chains held by various nodes will
have a common element. This allows such chains to be cross referenced in order to build a complete
picture of data from the start of the network. These side benefits of this feature are significant
and will be added to during this paper. In essence, this chain of verifiable data elements provides
a provable sequence of data validity and also the sequence of such data appearing on the network.

It is through this basic recondition of chained majority agreements that assures the ability for a
`DataChain` to be validated and therefore allows data to be republished.

The design described below will show a system where node capabilities are amortised across a network,
providing a balance of resources that can be mixed evenly across a network of nodes with varying
capabilities, form mass persistent data storage to very little, transient data storage.

# Motivation

In a fully decentralised network there are many problems to solve, two important issues are:

1. Transferring large amounts of data to replicant nodes on each churn event.

2. Enabling data to be republished in a secure manner.

Point 2 can be further sub divided. The ability to start a node and make it's data available is
obviously required where large amounts of data are required to be maintained. Another large
advantage is the ability for such a network to recover from a full system outage (full network
collapse, worldwide power outage etc.).

Another very useful "side effect" of data republish is in network upgrades. As long as two versions
of nodes have the ability to accept and store such data, even immediate stem wide  upgrades may be
an option, that was not previously possible. This component requires some further research, but
would appear to offer a significant advantage.

# Detailed design

## Data identifier object

A `DataChain` is a chained list of `DataIdentifiers` plus some form of cryptographic proof. A
`DataIdentifier` is an object that can uniquely identify and validate a data item. These identifiers
will hold a cryptographic hash of the underlying data item, but may also hold additional information
such as name, version ...etc...

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

As well as `DataIdentifier` each `NodeDataBlock` consists of a  `PublicKey/Signature` pair.  The
`PublicKey` can be proven to be the key that signed the `DataIdentifier` using the signature as the
proof.

**NB this assumes the PublicKey is in fact the node name (or can be extracted from) of a node close
to the `DataIdentifier`**

```rust

/// Sent by any group member when data is `Put`, `Post` or `Delete` in this group
#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug, Clone)]
pub struct NodeDataBlock {
    identifier: DataIdentifier,
    proof: (PublicKey, Signature),
    // Optionally we can include a UTC timestamp here and use this to note time of the data being
    // put on the network. As this is not exact in an eventual consistency network, the timestamp
    // would be the median value of a sorted list of timestamps per `DataBlock`
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
and then in the `DataChain` itself. On finding an entry it will add the node to any `DataBlock`. If
no entry is found the receiver will create a new `DataBlock` entry in the cache and await further
notifications from group members of this `DataIdentifier`.

This array must contain at least QUORUM members and be of CLOSE_GROUP length. It must only contain
nodes close to that data element described by the  `DataIdentifier`.

## Data chain

On accumulation of a majority of signatories, the `DataBlock` will be inserted into the `DataChain`
If it cannot be added (yet) due to lack of a majority consensus, it will remain in the cache and
await further `NodeDataBlock`'s.'

The `DataChain` is validated via a chain of signed elements where there is a majority of signatures
in agreement at each step (lock step). From the first element to the last, this chain of majority
signatures will show that the entire chain is valid. This is due to the fact that the current group
will also have a majority of current members in agreement with the previous entry.

**To maintain this security, on each churn event the last entry is refreshed to the whole group.
This is added to the chain if it still maintains consensus. If there are several churn events in
succession then there may be several copies of that entry in the chain. This is an unlikely event as
data should constantly be in flux in such a network, but as a safeguard there may be several entries
to maintain integrity of the chain.**

For this reason, duplicate entries are allowed to exist in the chain. In normal circumstances
duplicates will not exist, as chains are grown only with successful `Put`, `Post` or `Delete`. These
by their definition cannot be for same data.

A `Delete` event will, however, remove an entry from the chain, but only if the chained consensus
would not be broken. If such a delete did cause a gap in the consensus, effectively breaking the
chain, the entry would be maintained and marked as deleted (the actul data is deleted from any disk
cache).

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

# Requirements of network nodes

In a decentralised network, a large improvement in stability and ability for failure recovery can be
improved by a few simple steps :

1. Each node should store the nodes it has been connected to. (can be limited if required, as very
old node addreses are unlikely to reappear).

2. A node should store it's public and secret keys on disk along with it's data and associated
`DataChain`.

3. On startup a node should attempt to reconnect to the last address it recorded and present it's
`DataChain`. The group will decide (and should also have a note of this nodes address (key)) if this
node is allowed to join this group or instead have to join the network again to be allocated a new
address.
    -   The group will make this decision on the length of the nodes `DataChain`. If we consider
        three large nodes (Archive nodes) can exist per group. Then this node will join the group if
        it has a `DataChain` longer than the third longest `DataChain` in the group.

4. As nodes will attempt to hold persistent data, all local data can be held in named directories.
On startup this data will be useful if the node can rejoin a group.  If a node is rejected and
forced to rejoin the network with a new ID then a new named directory can be created. this allows
nodes to clean up unused directories effectively.

## Network restart

The process described above will mean that decentralised network, far from potentially losing data
on restart should recover with a very high degree of certainty.

As nodes will retain a list of previously connected nodes as well as attempt to rejoin a group then
each node can use it's "remembered" list of previously known node names to validate a majority
without the other nodes existing. This is a form of offline validation that can be extended further.
It allows offline validation for a node, but does not allow this validation to be sent to another
node. The remainder of the old group will have to form again to provide full validation.

# Additional observations

## Archive nodes

Nodes that hold the longest `DataChains` may be considered to be archive nodes. such nodes will be
responsible for maintaining all network data for specific areas of the network address range.

### Archive node Datachain length

The length of the `DataChain` should be as long as possible. Although a node may not require to hold
data outwith it's current close group. It is prudent such nodes hold as much of the Chain as
possible as this all allow quicker rebuild of a network on complete outage. Nodes may keep such
structures and associated data in a container that prunes older blocks to make space for new blocks
as new blocks appear.

#### Additional requirements of Archive nodes

If an archive nodes is requested data that is ouwith it's current close group then it should receive
a higher reward than usual. This will encourage nodes to maintain as much data as possible.

## Non Archive nodes

All nodes in a group will build on their `DataChain`, whether an Archive node or simply attempting
to become an archive node. Small nodes with little resources though may decide to not create a
`DataChain`. In these cases these smaller less capable nodes will receive limited rewards as they do
not have the ability to respond to many data retrieval requests, if any at all. These small nodes
though are still beneficial to the network to provide connectivity and lower level consensus at the
routing level.

## Chained chains

As chains grow and nodes hold longer chains across many disparate groups, there will be commonalties
on `DataBlocks` held. such links across chans has not as yet been fully analysed. It is speculated
that these links across chains provide may prove to be extremely useful.

## Timestamped order of data

With a small modification to a `DataBlock`, a list of timestamps can be obtained along with the
proof. The median value of such timtamps can be used to provide a certain range (within a day or
hour) of the publication date of any data item. This cna also be used to prove first version or
attribution of an initial creator of any digital information, regardless of copies existing and
possibly altered slightly.

### Structured data first version

To strengthen the validity of mutable data (StructuredData) the first version (version 0) may be
maintained in the chain. This will show age of such data, which may be particularly useful in types
of mutable data that do not change ownership or indeed where network created elements (such as any
currency) can be further validated.

## Archive node pointers

The possibility for a group to not have an ability, even with Archive nodes to store all data may
still exist in small imbalanced networks. Such groups may be able to delegate responsibility to
known larger nodes outwith their group, by passing data and also passing a `DtaChain` to prove
validity. This can introduce an addition ot the `DataChain` object to provide pointers to data. In
such cases the larger nodes should receive a proportion of any reward for doing so. It is, however,
doubtful this particular paradigm will have to be enforced if possible archive nodes are pushed
across groups as described above.


