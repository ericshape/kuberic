use std::io::{self, Write};

use kube::CustomResourceExt;
use kuberic_operator::crd::KubericSet;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut output = io::stdout().lock();
    serde_json::to_writer_pretty(&mut output, &KubericSet::crd())?;
    writeln!(output)?;
    Ok(())
}
