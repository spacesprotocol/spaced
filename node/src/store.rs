use std::{
    collections::{BTreeMap, BTreeSet},
    fs::OpenOptions,
    io,
    io::ErrorKind,
    mem,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use anyhow::Result;
use bincode::{config, Decode, Encode};
use protocol::{
    bitcoin::{hashes::Hash as HashUtil, BlockHash, OutPoint},
    hasher::{BidHash, KeyHash, OutpointHash, SpaceHash},
    prepare::DataSource,
    FullSpaceOut, Params, SpaceOut,
};
use serde::{Deserialize, Serialize};
use spacedb::{
    db::{Database, SnapshotIterator},
    fs::FileBackend,
    tx::{KeyIterator, ReadTransaction, WriteTransaction},
    Configuration, Hash, NodeHasher, Sha256Hasher,
};

use crate::source::RpcBlockId;

type SpaceDb = Database<Sha256Hasher>;
type ReadTx = ReadTransaction<Sha256Hasher>;
pub type WriteTx<'db> = WriteTransaction<'db, Sha256Hasher>;
type WriteMemory = BTreeMap<Hash, Option<Vec<u8>>>;

#[derive(Clone)]
pub struct Store(SpaceDb);

pub struct Sha256;

#[derive(Clone)]
pub struct LiveStore {
    pub store: Store,
    pub state: LiveSnapshot,
}

#[derive(Clone)]
pub struct LiveSnapshot {
    db: SpaceDb,
    params: Params,
    pub metadata: Arc<RwLock<StoreCheckpoint>>,
    staged: Arc<RwLock<Staged>>,
    snapshot: (u32, ReadTx),
}

pub struct Staged {
    /// Block height of latest snapshot
    snapshot_version: u32,
    /// Stores changes until committed
    memory: WriteMemory,
}

#[derive(Serialize, Deserialize, Encode, Decode, Clone, Eq, PartialEq, Debug)]
pub struct StoreCheckpoint {
    pub block_height: u32,
    #[bincode(with_serde)]
    pub block_hash: BlockHash,
    pub tx_count: u64,
}

impl StoreCheckpoint {
    pub fn block_id(&self) -> RpcBlockId {
        RpcBlockId {
            height: self.block_height,
            hash: self.block_hash,
        }
    }
}

impl Store {
    pub fn open(path: PathBuf) -> Result<Self> {
        let db = Self::open_db(path)?;
        Ok(Self(db))
    }

    pub fn memory() -> Result<Self> {
        let db = Database::memory()?;
        Ok(Self(db))
    }

    fn open_db(path_buf: PathBuf) -> anyhow::Result<Database<Sha256Hasher>> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path_buf)?;

        let config = Configuration::new().with_cache_size(1000000 /* 1MB */);
        Ok(Database::new(Box::new(FileBackend::new(file)?), config)?)
    }

    pub fn iter(&self) -> SnapshotIterator<Sha256Hasher> {
        return self.0.iter();
    }

    pub fn write(&self) -> Result<WriteTx> {
        Ok(self.0.begin_write()?)
    }

    pub fn begin(&self, params: &Params) -> Result<LiveSnapshot> {
        let snapshot = self.0.begin_read()?;
        let meta: StoreCheckpoint = if snapshot.metadata().len() == 0 {
            StoreCheckpoint {
                block_height: params.activation_block_height,
                block_hash: BlockHash::from_raw_hash(HashUtil::from_byte_array(
                    params.activation_block,
                )),
                tx_count: 0,
            }
        } else {
            snapshot.metadata().try_into()?
        };

        let version = meta.block_height;
        let live = LiveSnapshot {
            db: self.0.clone(),
            params: params.clone(),
            metadata: Arc::new(RwLock::new(meta)),
            staged: Arc::new(RwLock::new(Staged {
                snapshot_version: version,
                memory: BTreeMap::new(),
            })),
            snapshot: (version, snapshot),
        };

        Ok(live)
    }
}

pub trait ChainStore {
    fn rollout_iter(&self) -> Result<(RolloutIterator, ReadTx)>;
}

impl ChainStore for Store {
    fn rollout_iter(&self) -> Result<(RolloutIterator, ReadTx)> {
        let snapshot = self.0.begin_read()?;
        Ok((
            RolloutIterator {
                inner: snapshot.iter(),
                n: 0,
            },
            snapshot,
        ))
    }
}

#[derive(Encode, Decode)]
pub struct EncodableOutpoint(#[bincode(with_serde)] pub OutPoint);

impl From<OutPoint> for EncodableOutpoint {
    fn from(value: OutPoint) -> Self {
        Self(value)
    }
}

impl From<EncodableOutpoint> for OutPoint {
    fn from(value: EncodableOutpoint) -> Self {
        value.0
    }
}

pub trait ChainState {
    fn insert_spaceout(&self, key: OutpointHash, spaceout: SpaceOut);
    fn insert_space(&self, key: SpaceHash, outpoint: EncodableOutpoint);

    fn update_bid(&self, previous: Option<BidHash>, bid: BidHash, space: SpaceHash);

    fn get_space_info(
        &mut self,
        space_hash: &protocol::hasher::SpaceHash,
    ) -> anyhow::Result<Option<FullSpaceOut>>;
}

impl ChainState for LiveSnapshot {
    fn insert_spaceout(&self, key: OutpointHash, spaceout: SpaceOut) {
        self.insert(key, spaceout)
    }

    fn insert_space(&self, key: SpaceHash, outpoint: EncodableOutpoint) {
        self.insert(key, outpoint)
    }

    fn update_bid(&self, previous: Option<BidHash>, bid: BidHash, space: SpaceHash) {
        if let Some(previous) = previous {
            self.remove(previous);
        }
        self.insert(bid, space)
    }

    fn get_space_info(&mut self, space_hash: &SpaceHash) -> anyhow::Result<Option<FullSpaceOut>> {
        let outpoint = self.get_space_outpoint(space_hash)?;

        if let Some(outpoint) = outpoint {
            let spaceout = self.get_spaceout(&outpoint)?;

            return Ok(Some(FullSpaceOut {
                outpoint,
                spaceout: spaceout.expect("should exist if outpoint exists"),
            }));
        }
        Ok(None)
    }
}

impl LiveSnapshot {
    #[inline]
    pub fn is_dirty(&self) -> bool {
        self.staged.read().expect("read").memory.len() > 0
    }

    pub fn restore(&self, checkpoint: StoreCheckpoint) {
        let snapshot_version = checkpoint.block_height;
        let mut meta_lock = self.metadata.write().expect("write lock");
        *meta_lock = checkpoint;

        // clear all staged changes
        let mut staged_lock = self.staged.write().expect("write lock");
        *staged_lock = Staged {
            snapshot_version,
            memory: BTreeMap::new(),
        };
    }

    pub fn inner(&mut self) -> anyhow::Result<&ReadTx> {
        {
            let rlock = self.staged.read().expect("acquire lock");
            let version = rlock.snapshot_version;
            drop(rlock);

            self.update_snapshot(version)?;
        }
        Ok(&self.snapshot.1)
    }

    pub fn insert<K: KeyHash + Into<Hash>, T: Encode>(&self, key: K, value: T) {
        let value = bincode::encode_to_vec(value, config::standard()).expect("encodes value");
        self.insert_raw(key.into(), value);
    }

    pub fn get<K: KeyHash + Into<Hash>, T: Decode>(
        &mut self,
        key: K,
    ) -> spacedb::Result<Option<T>> {
        match self.get_raw(&key.into())? {
            Some(value) => {
                let (decoded, _): (T, _) = bincode::decode_from_slice(&value, config::standard())
                    .map_err(|e| {
                    spacedb::Error::IO(io::Error::new(ErrorKind::Other, e.to_string()))
                })?;
                Ok(Some(decoded))
            }
            None => Ok(None),
        }
    }

    pub fn remove<K: KeyHash + Into<Hash>>(&self, key: K) {
        self.remove_raw(&key.into())
    }

    #[inline]
    fn remove_raw(&self, key: &Hash) {
        self.staged
            .write()
            .expect("write lock")
            .memory
            .insert(*key, None);
    }

    #[inline]
    fn insert_raw(&self, key: Hash, value: Vec<u8>) {
        self.staged
            .write()
            .expect("write lock")
            .memory
            .insert(key, Some(value));
    }

    fn update_snapshot(&mut self, version: u32) -> anyhow::Result<()> {
        if self.snapshot.0 != version {
            self.snapshot.1 = self.db.begin_read()?;
            let meta: StoreCheckpoint = self.snapshot.1.metadata().try_into().map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::Other, "could not parse metdata")
            })?;

            assert_eq!(version, meta.block_height, "inconsistent db state");
            self.snapshot.0 = version;
        }
        Ok(())
    }

    pub fn get_raw(&mut self, key: &Hash) -> spacedb::Result<Option<Vec<u8>>> {
        let rlock = self.staged.read().expect("acquire lock");

        if let Some(value) = rlock.memory.get(key) {
            return match value {
                None => Ok(None),
                Some(value) => Ok(Some(value.clone())),
            };
        }

        let version = rlock.snapshot_version;
        drop(rlock);

        self.update_snapshot(version).map_err(|error| {
            spacedb::Error::IO(std::io::Error::new(std::io::ErrorKind::Other, error))
        })?;
        self.snapshot.1.get(key)
    }

    pub fn commit(&self, metadata: StoreCheckpoint, mut tx: WriteTx) -> Result<()> {
        let mut staged = self.staged.write().expect("write");
        let changes = mem::replace(
            &mut *staged,
            Staged {
                snapshot_version: metadata.block_height,
                memory: BTreeMap::new(),
            },
        );

        for (key, value) in changes.memory {
            match value {
                None => {
                    _ = {
                        tx = tx.delete(key)?;
                    }
                }
                Some(value) => tx = tx.insert(key, value)?,
            }
        }

        tx.metadata(metadata.to_vec())?;
        tx.commit()?;
        drop(staged);
        Ok(())
    }

    pub fn estimate_bid(&mut self, target: usize) -> anyhow::Result<u64> {
        let rollout = self.get_rollout(target)?;
        if rollout.is_empty() {
            return Ok(0);
        }
        let (priority, _) = rollout.last().unwrap();
        Ok(*priority as u64)
    }

    pub fn get_rollout(&mut self, target: usize) -> anyhow::Result<Vec<(u32, SpaceHash)>> {
        let skip = target * self.params.rollout_batch_size as usize;
        let entries =
            self.get_rollout_entries(Some(self.params.rollout_batch_size as usize), skip)?;

        Ok(entries)
    }

    pub fn get_rollout_entries(
        &mut self,
        limit: Option<usize>,
        skip: usize,
    ) -> anyhow::Result<Vec<(u32, SpaceHash)>> {
        // TODO: this could use some clean up
        let rlock = self.staged.read().expect("acquire lock");
        let mut deleted = BTreeSet::new();
        let memory: Vec<_> = rlock
            .memory
            .iter()
            .rev()
            .filter_map(|(key, value)| {
                if BidHash::is_valid(key) {
                    if value.is_some() {
                        let spacehash =
                            SpaceHash::from_slice_unchecked(value.as_ref().unwrap().as_slice());
                        Some((BidHash::from_slice_unchecked(key.as_slice()), spacehash))
                    } else {
                        deleted.insert(BidHash::from_slice_unchecked(key.as_slice()));
                        None
                    }
                } else {
                    None
                }
            })
            .map(|x| Ok(x))
            .collect();

        drop(rlock);

        let snapshot = self.inner()?;
        let db = KeyRolloutIterator {
            iter: snapshot.iter(),
        };

        let merger = MergingIterator::new(memory.into_iter(), db);
        merger
            // skip deleted items
            .filter_map(|x| match x.as_ref() {
                Ok((bid_hash, _)) => {
                    if deleted.contains(bid_hash) {
                        None
                    } else {
                        Some(x)
                    }
                }
                _ => None,
            })
            .map(|result| result.map(|(bidhash, spacehash)| (bidhash.priority(), spacehash)))
            .skip(skip)
            .take(limit.map_or(usize::MAX, |l| l))
            .collect()
    }
}

impl protocol::prepare::DataSource for LiveSnapshot {
    fn get_space_outpoint(
        &mut self,
        space_hash: &protocol::hasher::SpaceHash,
    ) -> protocol::errors::Result<Option<OutPoint>> {
        let result: Option<EncodableOutpoint> = self
            .get(*space_hash)
            .map_err(|err| protocol::errors::Error::IO(err.to_string()))?;
        Ok(result.map(|out| out.into()))
    }

    fn get_spaceout(&mut self, outpoint: &OutPoint) -> protocol::errors::Result<Option<SpaceOut>> {
        let h = OutpointHash::from_outpoint::<Sha256>(*outpoint);
        let result = self
            .get(h)
            .map_err(|err| protocol::errors::Error::IO(err.to_string()))?;
        Ok(result)
    }
}

impl TryFrom<&[u8]> for StoreCheckpoint {
    type Error = bincode::error::DecodeError;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let (meta, _): (StoreCheckpoint, _) = bincode::decode_from_slice(value, config::standard())
            .expect("could not parse metadata");
        Ok(meta)
    }
}

impl StoreCheckpoint {
    fn to_vec(&self) -> Vec<u8> {
        bincode::encode_to_vec(self, config::standard()).expect("encodes metadata")
    }
}

impl protocol::hasher::KeyHasher for Sha256 {
    fn hash(data: &[u8]) -> protocol::hasher::Hash {
        Sha256Hasher::hash(data)
    }
}

pub struct RolloutIterator {
    inner: KeyIterator<Sha256Hasher>,
    n: usize,
}

impl Iterator for RolloutIterator {
    type Item = spacedb::Result<(Hash, Vec<u8>)>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(result) = self.inner.next() {
            self.n += 1;

            match result {
                Ok((key, value)) => {
                    if BidHash::is_valid(&key) {
                        return Some(Ok((key, value)));
                    }
                }
                Err(error) => {
                    return Some(Err(error));
                }
            }
        }
        None
    }
}

struct KeyRolloutIterator {
    iter: KeyIterator<Sha256Hasher>,
}

impl Iterator for KeyRolloutIterator {
    type Item = anyhow::Result<(BidHash, SpaceHash)>;
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(result) = self.iter.next() {
            match result {
                Ok((key, value)) if BidHash::is_valid(&key) => {
                    let spacehash = SpaceHash::from_slice_unchecked(value.as_slice());
                    let bidhash = BidHash::from_slice_unchecked(key.as_slice());
                    return Some(Ok((bidhash, spacehash)));
                }
                Ok(_) => {
                    continue;
                }
                Err(error) => return Some(Err(error.into())),
            }
        }
        None
    }
}

struct MergingIterator<I1, I2>
where
    I1: Iterator<Item = Result<(BidHash, SpaceHash)>>,
    I2: Iterator<Item = Result<(BidHash, SpaceHash)>>,
{
    iter1: std::iter::Peekable<I1>,
    iter2: std::iter::Peekable<I2>,
}

impl<I1, I2> MergingIterator<I1, I2>
where
    I1: Iterator<Item = Result<(BidHash, SpaceHash)>>,
    I2: Iterator<Item = Result<(BidHash, SpaceHash)>>,
{
    fn new(iter1: I1, iter2: I2) -> Self {
        MergingIterator {
            iter1: iter1.peekable(),
            iter2: iter2.peekable(),
        }
    }
}

impl<I1, I2> Iterator for MergingIterator<I1, I2>
where
    I1: Iterator<Item = Result<(BidHash, SpaceHash)>>,
    I2: Iterator<Item = Result<(BidHash, SpaceHash)>>,
{
    type Item = Result<(BidHash, SpaceHash)>;

    fn next(&mut self) -> Option<Self::Item> {
        match (self.iter1.peek(), self.iter2.peek()) {
            (Some(Ok((bid_a, _))), Some(Ok((bid_b, _)))) => {
                if bid_a >= bid_b {
                    self.iter1.next()
                } else {
                    self.iter2.next()
                }
            }
            (Some(_), None) => self.iter1.next(),
            (None, Some(_)) => self.iter2.next(),
            (Some(Err(_)), _) => self.iter1.next(),
            (_, Some(Err(_))) => self.iter2.next(),
            (None, None) => None,
        }
    }
}
