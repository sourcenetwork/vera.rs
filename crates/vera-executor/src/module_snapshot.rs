//! Logical module values for one isolated execution branch.

use vera_modules::ModuleState;

/// Module values from a committed revision or a pending execution branch.
#[derive(Clone, Debug)]
pub struct ModuleSnapshot {
    /// Values read and changed by module execution.
    pub(crate) modules: ModuleState,
}

impl ModuleSnapshot {
    /// Logical changes from the supplied execution parent.
    pub fn changes_from(&self, parent: &Self) -> vera_modules::module_state::ModuleChanges {
        self.modules.diff_from(&parent.modules)
    }
}
