//! Module checkpoints aligned with execution call and creation frames.

use std::sync::{Arc, Mutex};

use revm::{
    Inspector,
    interpreter::{CallInputs, CallOutcome, CreateInputs, CreateOutcome},
};
use vera_modules::{acp::AcpModule, bulletin::BulletinModule, vera::VeraModule};

type Modules = (AcpModule, BulletinModule, VeraModule);

#[derive(Debug, Default)]
pub(super) struct ModuleJournal {
    pub(super) modules: Modules,
    frames: Vec<Option<Modules>>,
}

impl ModuleJournal {
    pub(super) const fn new(modules: Modules) -> Self {
        Self {
            modules,
            frames: Vec::new(),
        }
    }

    pub(super) fn begin(&mut self) {
        assert!(self.frames.is_empty(), "unfinished module transaction");
        self.frames.push(None);
    }

    pub(super) fn checkpoint(&mut self) -> Result<(), String> {
        let frame = self
            .frames
            .last_mut()
            .ok_or("module call has no execution checkpoint")?;
        if frame.is_none() {
            *frame = Some(self.modules.clone());
        }
        Ok(())
    }

    pub(super) fn changed(&self) -> bool {
        self.frames
            .last()
            .and_then(Option::as_ref)
            .is_some_and(|before| {
                !before.0.store().shares_values_with(self.modules.0.store())
                    || !before.1.store().shares_values_with(self.modules.1.store())
                    || !before.2.store().shares_values_with(self.modules.2.store())
            })
    }

    pub(super) fn writes_fit_native_bounds(&self) -> bool {
        self.frames
            .last()
            .and_then(Option::as_ref)
            .is_some_and(|before| {
                self.modules
                    .0
                    .store()
                    .changes_fit_native_bounds(before.0.store())
                    && self
                        .modules
                        .1
                        .store()
                        .changes_fit_native_bounds(before.1.store())
                    && self
                        .modules
                        .2
                        .store()
                        .changes_fit_native_bounds(before.2.store())
            })
    }

    fn end(&mut self, success: bool) {
        let before = self.frames.pop().expect("matching execution checkpoint");
        if let Some(before) = before {
            if !success {
                self.modules = before;
            } else if let Some(parent @ None) = self.frames.last_mut() {
                *parent = Some(before);
            }
        }
    }

    pub(super) fn finish(&mut self, success: bool) {
        if success && !self.frames.is_empty() {
            assert_eq!(self.frames.len(), 1, "unclosed execution frame");
            self.end(true);
        } else if !success {
            while !self.frames.is_empty() {
                self.end(false);
            }
        }
        assert!(self.frames.is_empty(), "unclosed module checkpoints");
    }
}

/// Rolls back module writes with REVM calls, including reverted child calls
/// whose errors are handled by a successful parent.
#[derive(Debug)]
pub struct ModuleInspector(pub(super) Arc<Mutex<ModuleJournal>>);

impl<CTX> Inspector<CTX> for ModuleInspector {
    fn call(&mut self, _: &mut CTX, _: &mut CallInputs) -> Option<CallOutcome> {
        self.0.lock().unwrap().frames.push(None);
        None
    }

    fn call_end(&mut self, _: &mut CTX, _: &CallInputs, outcome: &mut CallOutcome) {
        self.0.lock().unwrap().end(outcome.result.result.is_ok());
    }

    fn create(&mut self, _: &mut CTX, _: &mut CreateInputs) -> Option<CreateOutcome> {
        self.0.lock().unwrap().frames.push(None);
        None
    }

    fn create_end(&mut self, _: &mut CTX, _: &CreateInputs, outcome: &mut CreateOutcome) {
        self.0.lock().unwrap().end(outcome.result.result.is_ok());
    }
}
