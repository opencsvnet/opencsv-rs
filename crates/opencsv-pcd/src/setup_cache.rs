//! Bounded process-wide cache for expensive circuit setup data.
//!
//! A cache entry is keyed by the complete construction identity: canonical
//! circuit structure, setup/configuration parameters, pinned implementation
//! revision, and any predecessor verification-key identities. Cached setup
//! values are mutex-guarded because upstream `CircuitProverData` contains a
//! mutable ALU schedule cache and is intentionally not `Sync`.

use std::collections::{HashMap, VecDeque};
use std::fmt::Debug;
use std::sync::{Arc, Mutex, MutexGuard};

use p3_circuit::Circuit;
use sha2::{Digest as _, Sha256};

use crate::EF;

const IDENTITY_DOMAIN: &[u8] = b"opencsv-pcd/setup-identity/v1";
const UPSTREAM_REVISION: &[u8] =
    b"opencsvnet/plonky3-recursion/28c9a37f31a7f69877a62cb372ddffce1f3f8189";

/// Digest of every input that determines setup or verifier data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SetupIdentity([u8; 32]);

impl SetupIdentity {
    fn from_components(domain: &[u8], components: &[&[u8]], verification_keys: &[Self]) -> Self {
        let mut hasher = Sha256::new();
        hash_part(&mut hasher, IDENTITY_DOMAIN);
        hash_part(&mut hasher, UPSTREAM_REVISION);
        hash_part(&mut hasher, env!("CARGO_PKG_VERSION").as_bytes());
        hash_part(&mut hasher, domain);
        for component in components {
            hash_part(&mut hasher, component);
        }
        for verification_key in verification_keys {
            hash_part(&mut hasher, &verification_key.0);
        }
        Self(hasher.finalize().into())
    }

    /// Hash a circuit canonically enough to invalidate setup whenever any
    /// setup-relevant shape, operation, input layout or registered table
    /// changes. Maps are sorted before hashing to remove `HashMap` iteration
    /// nondeterminism.
    pub(crate) fn for_circuit(
        domain: &[u8],
        circuit: &Circuit<EF>,
        parameters: &[&[u8]],
        verification_keys: &[Self],
    ) -> Self {
        let mut circuit_hasher = Sha256::new();
        hash_debug(&mut circuit_hasher, &circuit.witness_count);
        hash_debug(&mut circuit_hasher, &circuit.ops);
        hash_debug(&mut circuit_hasher, &circuit.public_rows);
        hash_debug(&mut circuit_hasher, &circuit.public_flat_len);
        hash_debug(&mut circuit_hasher, &circuit.private_input_rows);
        hash_debug(&mut circuit_hasher, &circuit.private_flat_len);
        hash_sorted_debug(&mut circuit_hasher, circuit.enabled_ops.iter());
        hash_sorted_debug(&mut circuit_hasher, circuit.expr_to_widx.iter());
        hash_sorted_debug(
            &mut circuit_hasher,
            circuit.non_primitive_trace_generators.keys(),
        );
        hash_debug(
            &mut circuit_hasher,
            &circuit.non_primitive_trace_generator_order,
        );
        hash_sorted_debug(&mut circuit_hasher, circuit.tag_to_witness.iter());
        hash_sorted_debug(&mut circuit_hasher, circuit.tag_to_op_id.iter());
        if let Some(rewrites) = &circuit.witness_rewrite {
            hash_sorted_debug(&mut circuit_hasher, rewrites.iter());
        } else {
            hash_part(&mut circuit_hasher, b"no-witness-rewrite");
        }
        let circuit_digest: [u8; 32] = circuit_hasher.finalize().into();

        let mut components = Vec::with_capacity(parameters.len() + 1);
        components.push(circuit_digest.as_slice());
        components.extend_from_slice(parameters);
        Self::from_components(domain, &components, verification_keys)
    }

    /// Hash verification-key/common-data components for use as a parent
    /// identity in recursive setup keys.
    pub(crate) fn for_verification_key(domain: &[u8], components: &[&[u8]]) -> Self {
        Self::from_components(domain, components, &[])
    }
}

fn hash_part(hasher: &mut Sha256, part: &[u8]) {
    hasher.update((part.len() as u64).to_le_bytes());
    hasher.update(part);
}

fn hash_debug<T: Debug + ?Sized>(hasher: &mut Sha256, value: &T) {
    hash_part(hasher, format!("{value:?}").as_bytes());
}

fn hash_sorted_debug<'a, T, I>(hasher: &mut Sha256, values: I)
where
    T: Debug + 'a,
    I: IntoIterator<Item = T>,
{
    let mut values: Vec<_> = values
        .into_iter()
        .map(|value| format!("{value:?}"))
        .collect();
    values.sort_unstable();
    for value in values {
        hash_part(hasher, value.as_bytes());
    }
}

/// Shared handle for one setup. The mutex is part of the correctness
/// boundary, not merely a cache implementation detail.
pub(crate) type CachedSetup<T> = Arc<Mutex<T>>;

struct CacheState<T> {
    entries: HashMap<SetupIdentity, CachedSetup<T>>,
    oldest_first: VecDeque<SetupIdentity>,
    #[cfg(test)]
    hits: usize,
    #[cfg(test)]
    builds: usize,
}

/// Small bounded cache. Setup construction runs while the map lock is held,
/// guaranteeing at-most-once construction for a cold identity even when
/// callers arrive concurrently.
pub(crate) struct SetupCache<T> {
    capacity: usize,
    state: Mutex<CacheState<T>>,
}

impl<T> SetupCache<T> {
    pub(crate) fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "setup cache capacity must be non-zero");
        Self {
            capacity,
            state: Mutex::new(CacheState {
                entries: HashMap::new(),
                oldest_first: VecDeque::new(),
                #[cfg(test)]
                hits: 0,
                #[cfg(test)]
                builds: 0,
            }),
        }
    }

    pub(crate) fn get_or_try_insert_with<E>(
        &self,
        identity: SetupIdentity,
        build: impl FnOnce() -> Result<T, E>,
    ) -> Result<CachedSetup<T>, E> {
        let mut state = lock_unpoisoned(&self.state);
        if let Some(existing) = state.entries.get(&identity).cloned() {
            #[cfg(test)]
            {
                state.hits += 1;
            }
            touch(&mut state.oldest_first, identity);
            return Ok(existing);
        }

        let setup = Arc::new(Mutex::new(build()?));
        #[cfg(test)]
        {
            state.builds += 1;
        }
        while state.entries.len() >= self.capacity {
            let Some(evicted) = state.oldest_first.pop_front() else {
                state.entries.clear();
                break;
            };
            state.entries.remove(&evicted);
        }
        state.entries.insert(identity, Arc::clone(&setup));
        state.oldest_first.push_back(identity);
        Ok(setup)
    }

    #[cfg(any(test, feature = "d5-profile-spike"))]
    pub(crate) fn reset(&self) {
        let mut state = lock_unpoisoned(&self.state);
        state.entries.clear();
        state.oldest_first.clear();
        #[cfg(test)]
        {
            state.hits = 0;
            state.builds = 0;
        }
    }

    #[cfg(test)]
    fn stats(&self) -> (usize, usize, usize) {
        let state = lock_unpoisoned(&self.state);
        (state.entries.len(), state.hits, state.builds)
    }
}

fn touch(order: &mut VecDeque<SetupIdentity>, identity: SetupIdentity) {
    if let Some(index) = order.iter().position(|candidate| *candidate == identity) {
        order.remove(index);
    }
    order.push_back(identity);
}

pub(crate) fn lock_setup<T>(setup: &CachedSetup<T>) -> MutexGuard<'_, T> {
    lock_unpoisoned(setup)
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Barrier, OnceLock};
    use std::thread;

    use p3_circuit::CircuitBuilder;

    use super::*;

    fn test_lock() -> MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        lock_unpoisoned(LOCK.get_or_init(|| Mutex::new(())))
    }

    fn identity(component: &[u8]) -> SetupIdentity {
        SetupIdentity::from_components(b"test", &[component], &[])
    }

    fn circuit(private_inputs: usize) -> Circuit<EF> {
        let mut builder = CircuitBuilder::<EF>::new();
        let inputs = builder.alloc_private_inputs(private_inputs, "cache_identity");
        if inputs.len() >= 2 {
            let _ = builder.add(inputs[0], inputs[1]);
        }
        builder.build().expect("identity test circuit")
    }

    #[test]
    fn cold_then_warm_reuses_one_setup() {
        let _guard = test_lock();
        let cache = SetupCache::new(4);
        cache.reset();
        let cold = cache
            .get_or_try_insert_with(identity(b"same"), || Ok::<_, ()>(7usize))
            .expect("cold setup");
        let warm = cache
            .get_or_try_insert_with(identity(b"same"), || Ok::<_, ()>(99usize))
            .expect("warm setup");
        assert!(Arc::ptr_eq(&cold, &warm));
        assert_eq!(*lock_setup(&warm), 7);
        assert_eq!(cache.stats(), (1, 1, 1));
    }

    #[test]
    fn changed_identity_invalidates_and_capacity_evicts() {
        let _guard = test_lock();
        let cache = SetupCache::new(2);
        let first = cache
            .get_or_try_insert_with(identity(b"vk-a"), || Ok::<_, ()>(1usize))
            .expect("first");
        let second = cache
            .get_or_try_insert_with(identity(b"vk-b"), || Ok::<_, ()>(2usize))
            .expect("second");
        assert!(!Arc::ptr_eq(&first, &second));
        let _third = cache
            .get_or_try_insert_with(identity(b"vk-c"), || Ok::<_, ()>(3usize))
            .expect("third");
        let rebuilt = cache
            .get_or_try_insert_with(identity(b"vk-a"), || Ok::<_, ()>(4usize))
            .expect("evicted setup rebuilds");
        assert!(!Arc::ptr_eq(&first, &rebuilt));
        assert_eq!(*lock_setup(&rebuilt), 4);
        assert_eq!(cache.stats(), (2, 0, 4));
    }

    #[test]
    fn concurrent_cold_access_builds_once() {
        let _guard = test_lock();
        let cache = Arc::new(SetupCache::new(4));
        let barrier = Arc::new(Barrier::new(8));
        let builds = Arc::new(AtomicUsize::new(0));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let cache = Arc::clone(&cache);
            let barrier = Arc::clone(&barrier);
            let builds = Arc::clone(&builds);
            threads.push(thread::spawn(move || {
                barrier.wait();
                cache
                    .get_or_try_insert_with(identity(b"concurrent"), || {
                        builds.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, ()>(42usize)
                    })
                    .expect("concurrent setup")
            }));
        }
        let handles: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().expect("thread"))
            .collect();
        assert!(handles
            .iter()
            .all(|handle| Arc::ptr_eq(&handles[0], handle)));
        assert_eq!(builds.load(Ordering::SeqCst), 1);
        assert_eq!(cache.stats(), (1, 7, 1));
    }

    #[test]
    fn circuit_parameters_and_parent_vks_all_invalidate_identity() {
        let _guard = test_lock();
        let parent_a = identity(b"parent-a");
        let parent_b = identity(b"parent-b");
        let baseline =
            SetupIdentity::for_circuit(b"recursive", &circuit(2), &[b"fri-a"], &[parent_a]);
        assert_eq!(
            baseline,
            SetupIdentity::for_circuit(b"recursive", &circuit(2), &[b"fri-a"], &[parent_a],),
            "equivalent freshly built circuits have one stable identity"
        );
        assert_ne!(
            baseline,
            SetupIdentity::for_circuit(b"recursive", &circuit(3), &[b"fri-a"], &[parent_a],),
            "circuit shape invalidates"
        );
        assert_ne!(
            baseline,
            SetupIdentity::for_circuit(b"recursive", &circuit(2), &[b"fri-b"], &[parent_a],),
            "setup parameters invalidate"
        );
        assert_ne!(
            baseline,
            SetupIdentity::for_circuit(b"recursive", &circuit(2), &[b"fri-a"], &[parent_b],),
            "predecessor verification key invalidates"
        );
    }
}
