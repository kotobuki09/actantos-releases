// A WASI guest that probes its own containment boundary and reports what it found.
//
// This is the probe half of the Phase P WASI experiment. It is deliberately not a useful program:
// every subcommand is an attempt to learn something about the host that a well-behaved guest should
// not be able to learn. The Node side drives it under several different WASI configurations and
// compares what each one allowed.
//
// Output contract, one line per probe, on stdout. `OK ...` or `ERR <message>`. The Node side asserts
// on the prefix, because errno wording is a wasi-libc detail and not the thing under test.

use std::fs;
use std::io::Read;

// Generic over the error so each probe can report the error type its own std API returns, rather
// than being flattened into one lossy variant. The errno text is part of the finding.
fn probe<E: std::fmt::Display>(label: &str, result: Result<String, E>) {
    match result {
        Ok(value) => println!("OK {label} {value}"),
        Err(error) => println!("ERR {label} {error}"),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("help");

    match command {
        // Read a file by absolute path. This is the probe for "does WASI have ambient filesystem
        // authority, or only what it was handed". The answer is the latter, and the interesting
        // part is *where* the boundary sits: not at the process, not at the filesystem, but at the
        // preopen list the host chose to pass in.
        "read" => {
            let path = args.get(1).cloned().unwrap_or_default();
            probe(
                "read",
                fs::read_to_string(&path).map(|contents| format!("{}bytes", contents.len())),
            )
        }

        // Open a path for writing. Read-only authority and write authority are separate grants in
        // WASI, and a host that preopens a directory for reading gets no write through it.
        "write" => {
            let path = args.get(1).cloned().unwrap_or_default();
            probe("write", fs::write(&path, b"wasip1").map(|_| "written".to_string()))
        }

        // List a directory. A preopened directory is a capability to that subtree, including the
        // names inside it, so the preopen choice leaks directory structure and nothing more.
        "listdir" => {
            let path = args.get(1).cloned().unwrap_or_default();
            probe(
                "listdir",
                fs::read_dir(&path).map(|entries| {
                    let mut names: Vec<String> = entries
                        .filter_map(|entry| entry.ok())
                        .map(|entry| entry.file_name().to_string_lossy().into_owned())
                        .collect();
                    names.sort();
                    names.join(",")
                }),
            )
        }

        // Read a host environment variable. WASI preview 1 has `environ_get`, and Node's
        // implementation decides what to hand over.
        "env" => {
            let name = args.get(1).cloned().unwrap_or_default();
            probe(
                "env",
                std::env::var(&name).map(|value| value.replace('\n', "\\n")),
            )
        }

        // Open a TCP connection. wasi-libc compiles this, and the guest's fate at run time is the
        // interesting result: Node's WASI implements no socket syscalls at all.
        "tcp" => {
            let host = args.get(1).cloned().unwrap_or_default();
            let port: u16 = args.get(2).and_then(|p| p.parse().ok()).unwrap_or(443);
            probe(
                "tcp",
                std::net::TcpStream::connect((host.as_str(), port))
                    .map(|_| "connected".to_string()),
            )
        }

        // Open a UDP socket, for the same reason and to see whether the absence is specific to TCP.
        "udp" => {
            probe(
                "udp",
                std::net::UdpSocket::bind("127.0.0.1:0").map(|_| "bound".to_string()),
            )
        }

        // Read stdin. Node's WASI wires the parent's stdio in by default; whether the host keeps
        // that authority is a configuration choice, not a sandbox property.
        "stdin" => {
            let mut buffer = Vec::new();
            probe("stdin", std::io::stdin().read_to_end(&mut buffer).map(|n| format!("{n}bytes")))
        }

        // Current working directory. Included because it is a cheap way for a guest to learn where
        // it was placed, which is information a preopen misconfiguration then turns into authority.
        "cwd" => probe("cwd", std::env::current_dir().map(|p| p.display().to_string())),

        // Wall clock and randomness. Both are unconditionally available to a WASI guest, and both
        // are ambient in a way that matters: a nonce derived from `random_get` inside a guest that
        // can observe other guests' timing is weaker than one derived on the host.
        "clock" => probe(
            "clock",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| format!("{}ms", d.as_millis()))
                .map_err(|error| std::io::Error::other(error.to_string())),
        ),

        // Unpredictable bytes. Reached through `RandomState` rather than a direct `random_get`
        // declaration: wasi-libc in this toolchain does not export `random_get` to the guest, which
        // is itself a data point — the host's randomness is reached only where std chooses to reach
        // it, not by asking for it directly.
        "random" => {
            use std::collections::hash_map::RandomState;
            use std::hash::{BuildHasher, Hasher};

            let mut hasher = RandomState::new().build_hasher();
            hasher.write(b"actantos");
            probe::<std::io::Error>("random", Ok(format!("{:x}", hasher.finish())))
        }

        // Ask for a capability the host did not grant. `path_open` against a preopen that was never
        // passed is the cleanest possible statement of the boundary: the call is not merely denied,
        // the namespace it names does not exist for this guest.
        "escape" => {
            let path = args.get(1).cloned().unwrap_or_default();
            probe("escape", fs::read_to_string(&path).map(|c| format!("{}bytes", c.len())))
        }

        // Report the process's own arguments, to show they cross the boundary intact.
        "argv" => probe::<std::io::Error>("argv", Ok(args.join(" "))),

        other => {
            println!("ERR unknown {other}");
            println!("probes: read write listdir env tcp udp stdin cwd clock random escape argv");
        }
    }
}
