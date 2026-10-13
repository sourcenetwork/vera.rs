use commonware_runtime::{BufferPoolConfig, tokio};
use commonware_utils::{NZU32, NZUsize};
use std::num::NonZeroUsize;

use crate::{MAILBOX_SIZE, PAGE_CACHE_SIZE, PAGE_SIZE};

/// Configure reusable storage buffers for the node's shared page cache and I/O.
pub fn configure_storage_buffers(runtime: tokio::Config) -> tokio::Config {
    let parallelism = NonZeroUsize::new(runtime.worker_threads())
        .expect("the runtime requires at least one worker");
    runtime.with_storage_buffer_pool_config(storage_pool_config(parallelism))
}

fn storage_pool_config(parallelism: NonZeroUsize) -> BufferPoolConfig {
    let page_class = usize::from(PAGE_SIZE.get()).next_power_of_two();
    let page_buffers = u32::try_from(PAGE_CACHE_SIZE.get() + MAILBOX_SIZE.get())
        .expect("the configured page buffer count fits u32");

    // Cache construction holds every page slot. Keep separate capacity for I/O,
    // and prevent free buffers from accumulating in another worker's local cache.
    BufferPoolConfig::for_storage()
        .with_parallelism(parallelism)
        .with_size_class(NZUsize!(page_class), NZU32!(page_buffers))
        .with_max_thread_cache_capacity(NZUsize!(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_runtime::{
        BufferPool, buffer::paged::CacheRef, iobuf::PoolError, telemetry::metrics::Registry,
    };

    #[test]
    fn cached_pages_leave_reusable_buffers_for_concurrent_io() {
        let page_bytes = usize::from(PAGE_SIZE.get()).next_power_of_two();
        let mut registry = Registry::default();
        let default_pool = BufferPool::new(BufferPoolConfig::for_storage(), &mut registry);
        let default_cache = CacheRef::new(default_pool.clone(), PAGE_SIZE, PAGE_CACHE_SIZE);
        assert!(matches!(
            default_pool.try_alloc(page_bytes),
            Err(PoolError::Exhausted)
        ));
        drop(default_cache);
        drop(default_pool);

        let mut registry = Registry::default();
        let pool = BufferPool::new(storage_pool_config(NZUsize!(8)), &mut registry);
        let cache = CacheRef::new(pool.clone(), PAGE_SIZE, PAGE_CACHE_SIZE);
        std::thread::scope(|scope| {
            for worker in 0..8u8 {
                let pool = &pool;
                scope.spawn(move || {
                    for _ in 0..8 {
                        let mut buffers = (0..64)
                            .map(|_| pool.try_alloc_zeroed(page_bytes).unwrap())
                            .collect::<Vec<_>>();
                        for buffer in &mut buffers {
                            assert!(buffer.as_ref().iter().all(|byte| *byte == 0));
                            buffer.as_mut().fill(worker + 1);
                        }
                        assert!(
                            buffers.iter().all(|buffer| buffer
                                .as_ref()
                                .iter()
                                .all(|byte| *byte == worker + 1))
                        );
                    }
                });
            }
        });
        // The original cache remains alive throughout worker allocation and reuse.
        drop(cache);
        assert!(pool.try_alloc_zeroed(page_bytes).is_ok());
    }
}
