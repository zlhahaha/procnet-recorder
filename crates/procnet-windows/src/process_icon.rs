use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use procnet_core::{ProcessIcon, ProcessIconState, SystemSnapshot};

use crate::raw::process_icon::load_icon;

/// Safe, bounded cache that enriches platform-independent process snapshots with executable icons.
#[derive(Debug, Default)]
pub struct ProcessIconCache {
    by_path: BTreeMap<String, ProcessIconState>,
}

impl ProcessIconCache {
    /// Loads at most `maximum_new` previously unseen image paths and reuses all cached results.
    pub fn enrich(&mut self, snapshot: &mut SystemSnapshot, maximum_new: usize) {
        let mut loaded = 0_usize;
        for process in &mut snapshot.processes {
            let Some(path) = process.image_path.as_deref() else {
                process.icon = ProcessIconState::Unavailable;
                continue;
            };
            if let Some(icon) = self.by_path.get(path) {
                process.icon = icon.clone();
                continue;
            }
            if loaded >= maximum_new {
                continue;
            }
            loaded = loaded.saturating_add(1);
            let state = load_icon(Path::new(path)).map_or(ProcessIconState::Unavailable, |icon| {
                icon.map_or(ProcessIconState::Unavailable, |icon| {
                    ProcessIconState::Available(ProcessIcon {
                        width: icon.width,
                        height: icon.height,
                        rgba: Arc::from(icon.rgba),
                    })
                })
            });
            self.by_path.insert(path.to_owned(), state.clone());
            process.icon = state;
        }
    }
}

#[cfg(test)]
mod tests {
    use procnet_core::{ProcessIconState, ProcessKey, ProcessSnapshot, SystemSnapshot};

    use super::ProcessIconCache;

    #[test]
    fn cache_enriches_the_current_executable_and_reuses_the_result() {
        let path = std::env::current_exe().unwrap().display().to_string();
        let mut snapshot = SystemSnapshot {
            captured_at_unix_nanos: 1,
            process_names: vec![(std::process::id(), "procnet-windows-test.exe".to_owned())],
            processes: vec![ProcessSnapshot {
                key: ProcessKey {
                    pid: std::process::id(),
                    started_at_unix_nanos: 1,
                },
                name: "procnet-windows-test.exe".to_owned(),
                image_path: Some(path),
                icon: ProcessIconState::NotLoaded,
            }],
            connections: Vec::new(),
        };
        let mut cache = ProcessIconCache::default();
        cache.enrich(&mut snapshot, 1);
        let ProcessIconState::Available(icon) = &snapshot.processes[0].icon else {
            panic!("current executable icon was unavailable");
        };
        assert_eq!(icon.width, 32);
        assert_eq!(icon.height, 32);
        assert_eq!(icon.rgba.len(), 32 * 32 * 4);
        snapshot.processes[0].icon = ProcessIconState::NotLoaded;
        cache.enrich(&mut snapshot, 0);
        assert!(matches!(
            snapshot.processes[0].icon,
            ProcessIconState::Available(_)
        ));
    }
}
