//! Utility functions for Ethereum.

use ethereum_types::H256;
use hash256_std_hasher::Hash256StdHasher;
use hash_db::Hasher;
use sha3::{Digest, Keccak256};
use alloc::vec::Vec;
use trie_root::Value as TrieStreamValue;

/// Concrete `Hasher` impl for the Keccak-256 hash
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct KeccakHasher;
impl Hasher for KeccakHasher {
	type Out = H256;

	type StdHasher = Hash256StdHasher;

	const LENGTH: usize = 32;

	fn hash(x: &[u8]) -> Self::Out {
		H256::from_slice(Keccak256::digest(x).as_slice())
	}
}

/// Concrete `TrieStream` impl for the ethereum trie.
#[derive(Default)]
pub struct Hash256RlpTrieStream {
	stream: rlp::RlpStream,
}

impl trie_root::TrieStream for Hash256RlpTrieStream {
	fn new() -> Self {
		Self {
			stream: rlp::RlpStream::new(),
		}
	}

	fn append_empty_data(&mut self) {
		self.stream.append_empty_data();
	}

	fn begin_branch(
		&mut self,
		_maybe_key: Option<&[u8]>,
		_maybe_value: Option<TrieStreamValue>,
		_has_children: impl Iterator<Item = bool>,
	) {
		// an item for every possible nibble/suffix
		// + 1 for data
		self.stream.begin_list(17);
	}

	fn append_empty_child(&mut self) {
		self.stream.append_empty_data();
	}

	fn end_branch(&mut self, value: Option<TrieStreamValue>) {
		match value {
			Some(value) => match value {
				TrieStreamValue::Inline(value) => self.stream.append(&value),
				TrieStreamValue::Node(value) => self.stream.append(&value),
			},
			None => self.stream.append_empty_data(),
		};
	}

	fn append_leaf(&mut self, key: &[u8], value: TrieStreamValue) {
		self.stream.begin_list(2);
		self.stream.append_iter(hex_prefix_encode(key, true));
		match value {
			TrieStreamValue::Inline(value) => self.stream.append(&value),
			TrieStreamValue::Node(value) => self.stream.append(&value),
		};
	}

	fn append_extension(&mut self, key: &[u8]) {
		self.stream.begin_list(2);
		self.stream.append_iter(hex_prefix_encode(key, false));
	}

	fn append_substream<H: Hasher>(&mut self, other: Self) {
		let out = other.out();
		match out.len() {
			0..=31 => self.stream.append_raw(&out, 1),
			_ => self.stream.append(&H::hash(&out).as_ref()),
		};
	}

	fn out(self) -> Vec<u8> {
		self.stream.out().freeze().into()
	}
}

fn hex_prefix_encode(nibbles: &[u8], leaf: bool) -> impl Iterator<Item = u8> + '_ {
	let inlen = nibbles.len();
	let oddness_factor = inlen % 2;

	let first_byte = {
		let mut bits = ((inlen as u8 & 1) + (2 * leaf as u8)) << 4;
		if oddness_factor == 1 {
			bits += nibbles[0];
		}
		bits
	};
	core::iter::once(first_byte).chain(
		nibbles[oddness_factor..]
			.chunks(2)
			.map(|ch| ch[0] << 4 | ch[1]),
	)
}

/// Generates a trie root hash for a vector of key-value tuples
pub fn trie_root<I, K, V>(input: I) -> H256
where
	I: IntoIterator<Item = (K, V)>,
	K: AsRef<[u8]> + Ord,
	V: AsRef<[u8]>,
{
	trie_root::trie_root::<KeccakHasher, Hash256RlpTrieStream, _, _, _>(input, None)
}

/// Generates a key-hashed (secure) trie root hash for a vector of key-value tuples.
pub fn sec_trie_root<I, K, V>(input: I) -> H256
where
	I: IntoIterator<Item = (K, V)>,
	K: AsRef<[u8]>,
	V: AsRef<[u8]>,
{
	trie_root::sec_trie_root::<KeccakHasher, Hash256RlpTrieStream, _, _, _>(input, None)
}

/// Generates a trie root hash for a vector of values
pub fn ordered_trie_root<I, V>(input: I) -> H256
where
	I: IntoIterator<Item = V>,
	V: AsRef<[u8]>,
{
	trie_root::trie_root::<KeccakHasher, Hash256RlpTrieStream, _, _, _>(
		input
			.into_iter()
			.enumerate()
			.map(|(i, v)| (rlp::encode(&i), v)),
		None,
	)
}
