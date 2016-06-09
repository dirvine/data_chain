- Feature Name: Data Blocks
- Status: proposed
- Type: new feature
- Related components: (data, routing, vaults)
- Start Date: 08-03-2016
- RFC PR: (leave this empty)
- Issue number: (leave this empty)

# Summary

Data blocks are a container that allows large blocks of data to be maintained. These blocks can be
validated by a node on a network, close to the data name, to contain valid data that was
 guaranteed to have been correctly stored onto the network.

# Motivation

In a fully decentralised network there are many problems to solve, two of these issues can be
thought of as:

1. How to handle transferring large amounts of data to replicant nodes on each churn event.

2. How to allow data to be republished in a secure manner.

Point 2 actually encompasses two large issues in itself. The ability to start a node and make it's
data available is obviously required where we have large amounts of data to maintain. Another large
advantage is the ability for such a network to recover from a full system outage (full network
collapse, worldwide power outage etc.).

Another very useful "side effect" of data republish is in network upgrades. As long as two versions
of nodes have the ability to accept and store such data then even incompatible upgrades may be an
option, that was not previously possible. This component requires some further research, but would
appear to offer a significant advantage.

# Detailed design

## BlockDentifier

A [DataIdentifier][1] is simple enumeration that represents, either a `Data` item (`structuredData`
or `ImmutableData`).  The other type that can be represented in the `enum` is a `Link`. A `Link`
represents a valid group of nodes that is close to a point in the Xor address space. This point
changes with respect to changing nodes around any node. The representation of the link address in
the chain (which is not representative of the address of the data or the node) is the Xor of all
the current close group members of the current node. All close group members will recognise the
group of this node and this node will also know the close group of all of it's close nodes.

## Block

A `Block` is made up of a `DataIdentifier` and a vector of `PublicKey` and `Signature`.

## NodeBlock



## Chain


## Routing requirements




##When the network is growing

The data_block entries must be within the current close group of the claimant node

##When the network has shrunk

The data_block entries are allowed to be outwith the current close_group.


On receipt of a Refresh message that contains a DataBlock, the receiving node will confirm each
item the list of data names and types (DataIdentifier) are in it's close_group.

##Prevention of injection attacks

To prevent such data being simply created in an off-line attack. To prevent this, the node must
have existed in the network and be able to prove this. This does not completely prevent off-line
attacks, but certainly makes them significantly more difficult and increasingly so as the network
grows.

Each Refresh message received from a node is signed by that node to the claimant node. These
refresh messages

In network restarts there exists a window of opportunity for an injection attack. This is a case
where invalid SD in particular could be injected. To prevent this the StructuredData refresh
message must include the hash of the StructuredData element.

####Node memory

Each node id added to the routing table should be "remembered" by all nodes that see this node.
These remembered NodeId's will allow nodes to tie up refresh message node Id's with those found in
the `DataBlock` These "previously seen" nodes should be written to the nodes cache file for later
proof.


###Network "difficulty"

The distance of the furthest group member to a nodes own ID is regarded as network difficulty. In
small networks this will wildly fluctuate. This value must be written to the nodes configuration
file, in case of SAFE this is the vault configuration file.

###If list of existing data is zero

This is a network restart, therefore we accept these messages as is and confirm there are at least
GROUP_SIZE nodes signed such messages. The difficult measurement must match (or be less than) that
of the  current receiving node in the previous network,

###If network difficulty is reduced significantly (less than half previous)

Confirm at least one node in current group exits in the array in the list of that data element.

# Drawbacks

In very small networks (less than approx 3000) network difficulty is a fluctuating number, this can
probably not be prevented, but may allow unwanted data or in fact prevent valid data from being
refreshed.


# Alternatives

What other designs have been considered? What is the impact of not doing this?

# Unresolved questions

What parts of the design are still to be done?

[1]:
