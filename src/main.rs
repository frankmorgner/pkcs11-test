mod parser;
mod runner;
mod report;
use runner::P11TestRunner;
use clap::Parser;

#[derive(Parser, Debug)]
/// Run PKCS#11 XML Scripts
///
/// If no XML input files are specified, this program reads STDIN for PKCS#11 XML commands. All
/// commands are performed with the given PKCS#11 module in the order in which they appear at
/// the input.
///
/// The PKCS#11 XML script language is defined here (both version are supported)
/// - https://docs.oasis-open.org/pkcs11/pkcs11-profiles/v3.1/os/pkcs11-profiles-v3.1-os.html
/// - https://docs.oasis-open.org/pkcs11/pkcs11-profiles/v3.2/pkcs11-profiles-v3.2.html
#[command(version, about)]
struct Args {
    /// filename of the PKCS#11 module
    #[arg(short, long)]
    module: String,

    /// XML files with PKCS#11 commands
    #[arg(num_args(0..))]
    xml_files: Option<Vec<String>>,
}

/*
fn limit_to_string(l: &Limit) -> String {
    match l {
        Limit::Max(i) => i.to_string(),
        Limit::Infinite => "0".to_string(),
        Limit::Unavailable => "18446744073709551615".to_string()
    }
}

fn limit_to_usize(l: &Limit) -> usize {
    match l {
        Limit::Max(i) => *i as usize,
        Limit::Infinite => 0,
        Limit::Unavailable => 18446744073709551615
    }
}
*/

use std::io::{self, Read};

// 10 Megabyte = 10 * 1024 * 1024 Bytes
const MAX_BUFFER_SIZE: usize = 10_485_760;

fn process_stdin(runner: &mut P11TestRunner) -> Result<(), Box<dyn std::error::Error>> {
    let stdin = io::stdin();
    let mut handle = stdin.lock();

    let mut buffer = String::new();
    let mut buf = [0; 8192];
    let mut test_counter = 1;

    loop {
        if buffer.len() > MAX_BUFFER_SIZE {
            return Err("Input buffer exceeded 10 MB. Missing </PKCS11> tag or test case too large?".into());
        }
        let bytes_read = handle.read(&mut buf)?;
        if bytes_read == 0 {
            break;
        }
        buffer.push_str(&String::from_utf8_lossy(&buf[..bytes_read]));

        loop {
            if let Some(start_idx) = buffer.find("<PKCS11>") {
                // cut everything in fromt of starting tag
                if start_idx > 0 {
                    buffer.drain(..start_idx);
                }
                if let Some(end_idx) = buffer.find("</PKCS11>") {
                    let end_tag_len = "</PKCS11>".len();
                    let test_case: String = buffer.drain(..end_idx + end_tag_len).collect();
                    let name = format!("STDIN test {}", test_counter);

                    runner.run(&test_case)?;
                    report::print_report(&name);

                    test_counter += 1;
                    continue;
                } else {
                    // missing end tag
                    break;
                }
            } else {
                // no starting tag, throw everything away except what might be part of the starting
                // tag (7 characters)
                if buffer.len() > 7 {
                    let keep = buffer.len() - 7;
                    buffer.drain(..keep);
                }
                break;
            }
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let mut runner = unsafe { P11TestRunner::new(&args.module)? };

    if let Some(xml_files) = args.xml_files {
        for test in xml_files {
            let test_content = std::fs::read_to_string(&test)?;
            runner.run(&test_content.as_str())?;
            report::print_report(&test);
        }
    } else {
        process_stdin(&mut runner)?;
    }

    Ok(())
}

