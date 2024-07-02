use bdk::bitcoin::{bip32, Network};
use bdk::descriptor::DescriptorError;
use bdk::KeychainKind;
use bdk::keys::DerivableKey;
use bdk::miniscript::Tap;
use bdk::keys::IntoDescriptorKey;
use bdk::template::{DescriptorTemplate, DescriptorTemplateOut, P2TR};

// Spaces experimental derivation path
// m/200/<standard-bip-32-derivation-paths>
// for example P2TR would be
// m/200/86h/0h/0h/0/0
pub struct SpaceDerivation<K: DerivableKey<Tap>>(pub K, pub KeychainKind);
pub struct SpaceDerivationPublic<K: DerivableKey<Tap>>(pub K, pub bip32::Fingerprint, pub KeychainKind);

impl<K: DerivableKey<Tap>> DescriptorTemplate for SpaceDerivation<K> {
    fn build(self, network: Network) -> Result<DescriptorTemplateOut, DescriptorError> {
        P2TR(segwit_v1::make_bipxx_private(86, self.0, self.1, network)?).build(network)
    }
}

impl<K: DerivableKey<Tap>> DescriptorTemplate for SpaceDerivationPublic<K> {
    fn build(self, network: Network) -> Result<DescriptorTemplateOut, DescriptorError> {
        P2TR(segwit_v1::make_bipxx_public(86, self.0, self.1, self.2, network)?).build(network)
    }
}

macro_rules! expand_make_bipxx {
    ( $mod_name:ident, $ctx:ty ) => {
        mod $mod_name {
            use super::*;

            pub(super) fn make_bipxx_private<K: DerivableKey<$ctx>>(
                bip: u32,
                key: K,
                keychain: KeychainKind,
                network: Network,
            ) -> Result<impl IntoDescriptorKey<$ctx>, DescriptorError> {
                let mut derivation_path = Vec::with_capacity(5);
                derivation_path.push(bip32::ChildNumber::from_hardened_idx(200)?);
                derivation_path.push(bip32::ChildNumber::from_hardened_idx(bip)?);

                match network {
                    Network::Bitcoin => {
                        derivation_path.push(bip32::ChildNumber::from_hardened_idx(0)?);
                    }
                    _ => {
                        derivation_path.push(bip32::ChildNumber::from_hardened_idx(1)?);
                    }
                }
                derivation_path.push(bip32::ChildNumber::from_hardened_idx(0)?);

                match keychain {
                    KeychainKind::External => {
                        derivation_path.push(bip32::ChildNumber::from_normal_idx(0)?)
                    }
                    KeychainKind::Internal => {
                        derivation_path.push(bip32::ChildNumber::from_normal_idx(1)?)
                    }
                };

                let derivation_path: bip32::DerivationPath = derivation_path.into();

                Ok((key, derivation_path))
            }
            pub(super) fn make_bipxx_public<K: DerivableKey<$ctx>>(
                bip: u32,
                key: K,
                parent_fingerprint: bip32::Fingerprint,
                keychain: KeychainKind,
                network: Network,
            ) -> Result<impl IntoDescriptorKey<$ctx>, DescriptorError> {
                let derivation_path: bip32::DerivationPath = match keychain {
                    KeychainKind::External => vec![bip32::ChildNumber::from_normal_idx(0)?].into(),
                    KeychainKind::Internal => vec![bip32::ChildNumber::from_normal_idx(1)?].into(),
                };

                let source_path = bip32::DerivationPath::from(vec![
                    bip32::ChildNumber::from_hardened_idx(200)?,
                    bip32::ChildNumber::from_hardened_idx(bip)?,
                    match network {
                        Network::Bitcoin => bip32::ChildNumber::from_hardened_idx(0)?,
                        _ => bip32::ChildNumber::from_hardened_idx(1)?,
                    },
                    bip32::ChildNumber::from_hardened_idx(0)?,
                ]);

                Ok((key, (parent_fingerprint, source_path), derivation_path))
            }
        }
    };
}

expand_make_bipxx!(segwit_v1, Tap);
