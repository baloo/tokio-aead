extern crate stderrlog;

pub fn setup() {
    let _ = stderrlog::new()
        .verbosity(4)
        .init()
        .expect("Unable to setup logger");
}
