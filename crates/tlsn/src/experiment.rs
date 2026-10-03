//! Opt-in numeric phase telemetry. No transcript, identity or error data is
//! recorded.

pub(crate) struct Phase {
    #[cfg(feature = "experiment-telemetry")]
    started: Option<web_time::Instant>,
    #[cfg(feature = "experiment-telemetry")]
    name: &'static str,
    #[cfg(feature = "experiment-telemetry")]
    completed: bool,
}

impl Phase {
    pub(crate) fn start(_name: &'static str) -> Self {
        Self {
            #[cfg(feature = "experiment-telemetry")]
            started: tracing::enabled!(target: "tlsn::experiment", tracing::Level::INFO)
                .then(web_time::Instant::now),
            #[cfg(feature = "experiment-telemetry")]
            name: _name,
            #[cfg(feature = "experiment-telemetry")]
            completed: false,
        }
    }

    pub(crate) fn complete(self) {
        #[cfg(feature = "experiment-telemetry")]
        {
            let mut phase = self;
            phase.completed = true;
        }
    }
}

#[cfg(feature = "experiment-telemetry")]
impl Drop for Phase {
    fn drop(&mut self) {
        if let Some(started) = self.started {
            let elapsed_us = started.elapsed().as_micros().min(u64::MAX as u128) as u64;
            tracing::info!(
                target: "tlsn::experiment",
                phase = self.name,
                elapsed_us,
                completed = self.completed,
            );
        }
    }
}

#[cfg(all(test, feature = "experiment-telemetry"))]
mod tests {
    use super::*;
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
    };
    use tracing::{
        Event, Subscriber,
        field::{Field, Visit},
    };
    use tracing_subscriber::{Layer, layer::Context, prelude::*};

    #[derive(Default)]
    struct NumericEvent(BTreeMap<String, String>);

    impl Visit for NumericEvent {
        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.0.insert(field.name().into(), format!("{value:?}"));
        }
    }

    struct Capture(Arc<Mutex<Vec<NumericEvent>>>);

    impl<S: Subscriber> Layer<S> for Capture {
        fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
            assert_eq!(event.metadata().target(), "tlsn::experiment");
            let mut visitor = NumericEvent::default();
            event.record(&mut visitor);
            self.0.lock().unwrap().push(visitor);
        }
    }

    #[test]
    fn records_numeric_completion_and_abandoned_phase_without_payloads() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(Capture(events.clone()));
        tracing::subscriber::with_default(subscriber, || {
            Phase::start("prover.mpc.preprocess").complete();
            // Error returns and cancelled futures drop their active scope.
            drop(Phase::start("prover.prove"));
        });

        let events = events.lock().unwrap();
        assert_eq!(events.len(), 2);
        for event in events.iter() {
            assert_eq!(event.0.len(), 3);
            assert!(event.0["elapsed_us"].parse::<u64>().is_ok());
        }
        assert_eq!(events[0].0["phase"], "\"prover.mpc.preprocess\"");
        assert_eq!(events[0].0["completed"], "true");
        assert_eq!(events[1].0["completed"], "false");
    }
}
