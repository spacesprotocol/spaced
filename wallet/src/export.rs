// Bitcoin Dev Kit
// Written in 2020 by Alekos Filini <alekos.filini@gmail.com>
//
// Copyright (c) 2020-2021 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.
// source: https://github.com/bitcoindevkit/bdk/blob/a5d076f215cd91173f55bda0d1cc59b9dde75511/crates/wallet/src/wallet/export.rs
use core::{fmt, str::FromStr};

use bdk_wallet::{KeychainKind, Wallet};
use serde::{Deserialize, Serialize};

/// Structure that contains the export of a wallet
///
/// For a usage example see [this module](crate::wallet::export)'s documentation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletExport {
    pub descriptor: String,
    /// Earliest block to rescan when looking for the wallet's transactions
    pub blockheight: u32,
    /// Arbitrary label for the wallet
    pub label: String,
}

impl fmt::Display for WalletExport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(self).unwrap())
    }
}

impl FromStr for WalletExport {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

fn remove_checksum(s: String) -> String {
    s.split_once('#').map(|(a, _)| String::from(a)).unwrap()
}

impl WalletExport {
    /// Export a wallet
    ///
    /// This function returns an error if it determines that the `wallet`'s descriptor(s) are not
    /// supported by Bitcoin Core or don't follow the standard derivation paths defined by BIP44
    /// and others.
    ///
    /// If `include_blockheight` is `true`, this function will look into the `wallet`'s database
    /// for the oldest transaction it knows and use that as the earliest block to rescan.
    ///
    /// If the database is empty or `include_blockheight` is false, the `blockheight` field
    /// returned will be `0`.
    pub fn export_wallet(
        wallet: &Wallet,
        label: &str,
        blockheight: u32,
    ) -> Result<Self, &'static str> {
        let descriptor = wallet
            .public_descriptor(KeychainKind::External)
            .to_string_with_secret(
                &wallet
                    .get_signers(KeychainKind::External)
                    .as_key_map(wallet.secp_ctx()),
            );
        let descriptor = remove_checksum(descriptor);

        let export = WalletExport {
            descriptor,
            label: label.into(),
            blockheight,
        };

        let change_descriptor = {
            let descriptor = wallet
                .public_descriptor(KeychainKind::Internal)
                .to_string_with_secret(
                    &wallet
                        .get_signers(KeychainKind::Internal)
                        .as_key_map(wallet.secp_ctx()),
                );
            Some(remove_checksum(descriptor))
        };

        if export.change_descriptor() != change_descriptor {
            return Err("Incompatible change descriptor");
        }

        Ok(export)
    }

    /// Return the external descriptor
    pub fn descriptor(&self) -> String {
        self.descriptor.clone()
    }

    /// Return the internal descriptor, if present
    pub fn change_descriptor(&self) -> Option<String> {
        let replaced = self.descriptor.replace("/0/*", "/1/*");

        if replaced != self.descriptor {
            Some(replaced)
        } else {
            None
        }
    }
}
