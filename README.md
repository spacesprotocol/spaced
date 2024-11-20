# Bitcoin Spaces

Checkout [releases](https://github.com/spacesprotocol/spaces/releases) for an immediately usable binary version of this software.


## What does it do?

Spaces are sovereign Bitcoin identities. They leverage the existing infrastructure and security of Bitcoin without requiring a new blockchain or any modifications to Bitcoin itself [learn more](https://spacesprotocol.org).


`spaced` is a tiny layer that connects to Bitcoin Core over RPC and scans transactions relevant to the protocol.

`space-cli` is a Bitcoin wallet that supports opening auctions, bidding and registering spaces.

## Quick Start

Check out the [documentation](https://docs.spacesprotocol.org) 

## Development setup on testnet4

### Install Bitcoin Core
Bitcoin Core of version 28+ is required. It can be installed from the official [download page](https://bitcoincore.org/en/download/).

### Install Spaces Daemon

`spaced` is a tiny layer that connects to Bitcoin Core over RPC and scans transactions relevant to the protocol. Make sure you have [Rust](https://www.rust-lang.org/tools/install) installed before proceeding.

```sh
git clone https://github.com/spacesprotocol/spaced && cd spaced
cargo install --path node --locked
```

Make sure it's in your path

```sh
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

Verify installation

```
spaced --version
space-cli --version
```

### Setup

First, download Bitcoin Core and set it up to connect to `testnet4` using these steps:

```sh
mkdir $HOME/bitcoin-testnet4

# Create a configuration file with RPC credentials
echo "rpcuser=testnet4" > $HOME/bitcoin-testnet4/bitcoin.conf
echo "rpcpassword=testnet4" >> $HOME/bitcoin-testnet4/bitcoin.conf

# Start Bitcoin Core specifying testnet4 network
bitcoind -testnet4 -datadir=$HOME/bitcoin-testnet4
```

Next, run spaced with the following:
```sh
spaced --chain testnet4 --bitcoin-rpc-user testnet4 --bitcoin-rpc-password testnet4
```

## Project Structure

| Package  | Requires std     | Description                                    |
|----------|------------------|------------------------------------------------|
| node     | Yes              | Daemon and wallet service                      |
| wallet   | Yes (no-std WIP) | wallet library for building spaces transactions|
| protocol | No               | Protocol consensus library                     |


## License

Spaces is released under the terms of the MIT license. See LICENSE for more information or see https://opensource.org/licenses/MIT.