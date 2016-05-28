# DataChain's

A data structure that may be cryptographically proven to contain valid data that has been secured
onto a decentralised network.

# Definitions used

- Decentralised network, A peer to peer network in xor space, using Kadmelia type addressing.
- Hash, a cryptographic one way function that produces a fixed length representation of any input.
- Immutable data, a data type that has a name == hash of it's contents (it is immutable as changing
  the contents creates a new peice of immutable data).
- Structured data, a data type that has a fixed name, but mutable contents.
- GROUP_SIZE, the number of nodes surrounding a network address.
- QUORUM, the number of the GROUP that is considered large enough that a decision is valid. In this
  paper this number is considered a majority (i.e. (GROUP_SIZE / 2) + 1)
- Chain consensus, the fact that QUORUM number of signatories exist in the next link (`DataBlock` as
  described below) that also exist in the previous block.
- Churn event, a change in the group, either by a node leaving or a node joining.

# Abstract

A mechanism to lock data descriptors in containers that may be held on a decentralised network.
Such structures are cryptographically secured in lock step using a consensus of cryptographic
signatures. These signatures are of a certain size GROUP_SIZE (e.g. 12 nodes) with a QUORUM (e.g. 7
nodes) required to be considered valid (much like N of P sharing). In a decentralised network that
has secured groups,these signatures are those closest to the holder of a `DataChain`. The
`DataChain` will have a majority of existing group members if it is republished prior to more than
GROUP_SIZE - QUORUM nodes changing. In this situation, there is a strong cryptographic proof of the
data validity.

When a `DataChain` starts, the first item is a `link`. This is a block that uses the identity of a
close group on the network. This `link` has an associated proof that is the `PublicKey` and a
corresponding signature for each node. The `Signature` is the signed `link` block.  On each `churn`
event a new link is created and again signed by all members of the close_group. This link is the
nodes close group as known by all members of that close_group. The link is the hash of that
close_group.

Data block entries are signed by an ever changing majority of pre-existing nodes.  As the chain
grows, this rolling majority of different signatories can be cryptographically confirmed (via
`links`).  This process continues to the very top of the chain which will contain entries signed by
the majority of the current close group of nodes. This current group of nodes can cryptographically
validate the entire chain and every data element referred to within it in reverse order.

A data chain may look like

`link:data:data:data:data:link:link:data:data`

or

`link:link:link:data:link:link:link:data:link`

The `links` maintain group consensus and the data elements should be individually validate all data
blocks though the group consensus provided by the preceding `link`.

As groups change and the network grows, or indeed shrinks, many chains held by various nodes will
have a common element. This allows such chains to be cross referenced in order to build a complete
picture of data from the start of the network. In essence, this chain of verifiable data elements
provides a provable sequence of data validity and also the sequence of such data appearing on the
network.

It is through this basic recondition of chained majority agreements that assures the ability for a
`DataChain` to be validated and therefore allows data to be republished.

The design described below will show a system where node capabilities are amortised across a
network, providing a balance of resources that can be mixed evenly across a network of nodes with
varying capabilities, form mass persistent data storage to very little, transient data storage.

# Motivation

In a fully decentralised network there are many problems to solve, two important issues are:

1. Transferring large amounts of data to replicant nodes on each churn event.

2. Enabling data to be republished in a secure manner.

Point 2 can be further sub divided. The ability to start a node and make its data available is
required where large amounts of data are required to be maintained. Another large advantage is the
ability for such a network to recover from a full system outage, such as a full network collapse, or
worldwide power outage, for example.

Furthermore, another very useful "side effect" of data republish is in network upgrades. As long as
two versions of nodes have the ability to accept and store such data, even immediate stem wide
upgrades may be an option, that was not previously possible. This component requires some further
research, but would appear to offer a significant advantage.

# Detailed design

## Data identifier object

A `DataChain` is a chained list of `DataBlock`'s which are comprised of `DataIdentifiers` that have
been cryptographically validated. A `DataIdentifier` is an object that can uniquely identify and
validate a data item. These identifiers will hold a cryptographic hash of the underlying data item,
but may also hold additional information such as name, version ...etc...

```rust
pub enum DataIdentifier {
    Immutable(sha512),
    Structured(sha512, XorName, u64),
    //         hash    name     version
    GroupIdentifier(sha512), // A special entry to agree on hash of current group (used in churn
    events) }

impl DataIdentifier {

pub fn name(&self) -> Option<XorName> {
    match *self {
        DataIdentifier::Immutable(hash) => Some(XorName::new(hash)),
        DataIdentifier::Structured(_, name, _) =>Some(name),
        _ => None // links have no name
    }
}

}

```

## Proof of block

There are two proof types as described below :

```rust
pub enum Proof {
    Link([(PublicKey, Option<Signature>); GROUP_SIZE]),
    Block([Option<Signature>; GROUP_SIZE]),
}
```

A link proof contains all `PublicKeys` of group members. On construction it will contain no
signatures as these are waiting to be received by the current node. On successful receipt of a
majority of the group members then this link is valid. Several links may appear in order on the
`chain`.

A `Block` proof contains an array of optional signatures. As each group member agrees to a `Put`,
`Post` or `Delete` request then this array is filled in. To allow the chain to be as compact as
possible, the `Block` proof contains only signatures and these are in the same order as the `link`
proofs.

## Node data block

As well as `DataIdentifier` each `NodeDataBlock` consists of a  `PublicKey/Signature` pair.  The
`PublicKey` can be proven to be the key that signed the `DataIdentifier` using the signature as the
proof.

**NB this assumes the PublicKey is in fact the node name (or can be extracted from) of a node close
to the `DataIdentifier`**

```rust

/// If data block then this is semt by any group member when data is `Put`, `Post` or `Delete`.
/// If this is a link then it is sent with a `churn` event.
#[derive(RustcEncodable, RustcDecodable, PartialEq, Debug, Clone)]
pub struct NodeBlock {
    identifier: BlockIdentifier,
    proof: (PublicKey, Signature),
}

impl NodeBlock {
    /// Create a Block (used by nodes in network to send to holders of `DataChains`)
    pub fn new(pub_key: &PublicKey,
               secret_key: &SecretKey,
               data_identifier: BlockIdentifier)
               -> Result<NodeBlock, Error> {
        let signature =
            crypto::sign::sign_detached(&try!(serialisation::serialise(&data_identifier))[..],
                                        secret_key);

        Ok(NodeBlock {
            identifier: data_identifier,
            proof: (pub_key.clone(), signature),
        })

        Ok(NodeBlock { identifier: data_identifier, proof: (pub_key.clone(), signature), })

    } }

```

## Data block

This array must contain at least QUORUM members signatures and be of CLOSE_GROUP length. It must
only contain nodes close to that data element described by the  `DataIdentifier`. This is enforced
at the time of insertion into the block `proof`.

## Data chain

The `DataChain` is validated via a chain of signed elements where there is a majority of signatures
in agreement at each `link` step (lock step). From the first element to the last, this chain of
majority signatures will show that the entire chain is valid. This is due to the fact that the
current group will also have a majority of current members in agreement with the previous entry.
**N:B The current signatories sign the current `DataIDentifier` and the previous `link`.**

**To maintain this security, on each churn event each node in the new group must sign an entry in
the chain that is the current group. The current group is all of the nodes in the current group with
relation to this `DataChain`. This must be done on every churn event to ensure no nodes can be later
inserted into the chain. There are several mechanisms to allow this such as a parallel chain of
nodes and groups or indeed insert into the chain a special `DataBlock` which is in fact the group
agreement block (`link`).**

The `DataChain` is described below.

```rust

pub struct DataChain {
    chain: Vec<DataBlock>,
    group_size: u64,
}


```

# Requirements of network nodes

In a decentralised network, a large improvement in stability and ability for failure recovery can be
improved by a few simple steps :

1. Each node should store the nodes it has been connected to (can be limited if required, as very
old node addreses are unlikely to reappear).

2. A node should store its public and secret keys on disk along with its data and associated
`DataChain`.

3. On startup, a node should attempt to reconnect to the last address it recorded and present its
`DataChain`. The group will decide (and should also have a note of this nodes address (key)) if this
node is allowed to join this group. Alternatively the node may have to join the network again to be
allocated a new address.
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

As nodes will retain a list of previously connected nodes, as well as attempt to rejoin a group,
each node can use its "remembered" list of previously known node names to validate a majority
without the other nodes existing. This is a form of offline validation that can be extended further.
It allows offline validation for a node, but does not allow this validation to be sent to another
node. The remainder of the old group will have to form again to provide full validation.

# Additional observations

## Archive nodes

Nodes that hold the longest `DataChains` may be considered to be archive nodes. such nodes will be
responsible for maintaining all network data for specific areas of the network address range. There
will be 3 archive nodes per group. These more reliable nodes have a vote weight of 2 within a group
and it would therefore require a minimum of 3 groups of archive nodes to collude against the
network. It is important to note that each group is chosen at random by the network.

### Archive node Datachain length

The length of the `DataChain` should be as long as possible. Although a node may not require to hold
data outwith it's current close group. It is prudent such nodes hold as much of the Chain as
possible as this all allow quicker rebuild of a network on complete outage. Nodes may keep such
structures and associated data in a container that prunes older blocks to make space for new blocks
as new blocks appear (FIFO or first in first out).

#### Additional requirements of Archive nodes

If an archive node requests data that is outwith its current close group, it should receive a higher
reward than usual. This reward is provided via a crypto graphic token which can be exchanged for
network services or for other forms of crypto currency, such as bitcoin, via an online exchange.
This incentive will encourage nodes to maintain as much data as possible.

## Non Archive nodes

All nodes in a group will build on their `DataChain`, whether an Archive node or simply attempting
to become an archive node. Small nodes with little resources though may find it difficult to create
a `DataChain`of any significance. In these cases these smaller less capable nodes will receive
limited rewards as they do not have the ability to respond to many data retrieval requests, if any
at all. These small nodes though are still beneficial to the network to provide connectivity and
lower level consensus at the routing level.

A non archive node can request old data from existing archive nodes in a group, but the rate should
be limited in cases where there are already three such nodes in a group. These messages will be the
lowest priority messages in the group. Tehreby any attacker will require to become an archive node
and this will take time, unless the group falls below three archive nodes in which case the priority
is increased on such relocation messages.

## Chained chains

As chains grow and nodes hold longer chains across many disparate groups, there will be commonalties
on `DataBlocks` held. Such links across chains has not as yet been fully analysed, however, it is
speculated that the ability to cross reference will enable a fuller picture of network data to be
built up.

## Timestamped order of data

With a small modification to a `DataBlock`, a list of timestamps can be obtained along with the
proof. The median value of such timestamps can be used to provide a certain range (within a day or
hour) of the publication date of any data item. This can also be used to prove first version or
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


