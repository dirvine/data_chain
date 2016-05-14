# DataChain's

A data structure that may b cryptographically proven to contain valid data that has been secured
onto a decentralised network.

# Abstract

A mechanism to lock data descriptors in a containers that may be held on a decentralised network.
Such structures are cryptographically secured in lock step using a consensus of cryptographic
signatures. These signatures are of a certain size GROUP_SIZE with a QUORUM required to be
considered valid. In a decentralised network that has secured groups, these signatures are those
closest to the holder of a `DataChain`. The `DataChain` will have a majority of existing group
members if it is republished prior to more than GROUP_SIZE - QUORUM nodes changing. In this
situation there is a strong cryptographic proof of the data validity.

It is though this recondition that assures the ability for a `DataChain` to be validated and
therefore allows data to be republished.

# Summary

Data blocks are a container that allows large blocks of data to be maintained. These blocks can be
validated by a node on a network, close to the data name, to contain valid data that was very likely (if not almost
guaranteed).to have been correctly stored onto the network.

# Motivation

In a fully decentralised network there are many problems to solve, two of these issues can be thought of
as:

1. How to handle transferring large amounts of data to replicant nodes on each churn event.

2. How to allow data to be republished in a secure manner.

Point 2 actually encompasses two large issues in itself. The ability to start a node and make it's data
available is obviously required where we have large amounts of data to maintain. Another large advantage
is the ability for such a network to recover from a full system outage (full network collapse, worldwide
power outage etc.).

Another very useful "side effect" of data republish is in network upgrades. As long as two versions of
nodes have the ability to accept and store such data then even incompatible upgrades may be an option, that
was not previously possible. This component requires some further research, but would appear to offer a
significant advantage.

# Detailed design

A data block can be defined as:

A list of data type names that the node had stored over at least one session XXXXXXXXXXXXXX. The name of such a container
is derived as `sha512(all names) xor NodeName`. Proof that this node was responsible for these chunks
involves several checks.

1. The claiming node must sign the list with the private key of the `data block`.
2. The `DataBlock.key()` must provide the public key of the claiming node.
3. The claiming nodes ID must be in the close_group of the data_block.
4. The list of data types must contain data types greater than the number currently held by the group
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
