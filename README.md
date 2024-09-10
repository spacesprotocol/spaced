# Spaced - Bitcoin Spaces daemon

Spaces is a naming protocol that leverages the existing infrastructure and security of Bitcoin without requiring a new blockchain or any modifications to Bitcoin itself [learn more](https://spacesprotocol.org).

## Project Structure

| Package  | Requires std     | Description                                    |
|----------|------------------|------------------------------------------------|
| node     | Yes              | Daemon and wallet service                      |
| wallet   | Yes (no-std WIP) | wallet library for building spaces transactions|
| protocol | No               | Protocol consensus library                     |

## Setup

First, download Bitcoin Core and set it up to connect to `regtest`
using these steps:

```bash
# Create a directory for Bitcoin regtest data
mkdir $HOME/bitcoin-testnet4

# Create a configuration file with RPC credentials
echo "rpcuser=testnet4" > $HOME/bitcoin-testnet4/bitcoin.conf
echo "rpcpassword=testnet4" >> $HOME/bitcoin-testnet4/bitcoin.conf

# Start Bitcoin Core specifying testnet4 network
bitcoind -testnet4 -datadir=$HOME/bitcoin-testnet4
```

```bash
git clone https://github.com/spacesprotocol/spaced && cd spaced
cargo build
```

Connect `spaced` to Bitcoin core

```bash
spaced --chain testnet4 --bitcoin-rpc-user testnet4 --bitcoin-rpc-password testnet4
```
