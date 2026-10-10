//! Allocator accounting for opt-in resource diagnostics.

use std::collections::BTreeMap;

pub(crate) fn snapshot() -> BTreeMap<&'static str, Option<usize>> {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    let values = {
        // SAFETY: mallinfo2 takes no pointers and returns counters by value.
        // The allocator is already initialized; glibc locks each arena while sampling.
        let memory = unsafe { libc::mallinfo2() };
        [
            Some(memory.arena),
            Some(memory.uordblks),
            Some(memory.fordblks),
            Some(memory.hblkhd),
        ]
    };
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    let values = [None; 4];

    [
        "arena_reserved",
        "arena_in_use",
        "arena_free",
        "direct_mapped",
    ]
    .into_iter()
    .zip(values)
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocator_snapshot_matches_platform_accounting() {
        let memory = snapshot();
        assert_eq!(memory.len(), 4);
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            assert!(memory.values().all(Option::is_some));
            assert_eq!(
                memory["arena_reserved"],
                memory["arena_in_use"]
                    .unwrap()
                    .checked_add(memory["arena_free"].unwrap())
            );
        }
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        assert!(memory.values().all(Option::is_none));
    }
}
