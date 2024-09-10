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
mkdir $HOME/bitcoin-regtest
echo "rpcuser=test" > $HOME/bitcoin-regtest/bitcoin.conf
echo "rpcpassword=test" >> $HOME/bitcoin-regtest/bitcoin.conf
bitcoind -regtest -datadir=$HOME/bitcoin-regtest
```

```bash
git clone https://github.com/spacesprotocol/spaced && cd spaced
cargo build
```

Connect `spaced` to Bitcoin core

```bash
spaced --chain regtest --bitcoin-rpc-user test --bitcoin-rpc-password test
```
