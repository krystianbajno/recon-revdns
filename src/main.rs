use clap::{Arg, ArgAction, Command, value_parser};
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::net::{IpAddr, ToSocketAddrs};
use std::process;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;
use trust_dns_client::client::{Client, SyncClient};
use trust_dns_client::rr::{DNSClass, Name, RecordType};
use trust_dns_client::udp::UdpClientConnection;
use trust_dns_client::tcp::TcpClientConnection;

const DEFAULT_RESOLVERS: [&str; 20] = [
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220", "64.6.64.6", "64.6.65.6", "198.101.242.72",
    "198.101.242.72", "8.26.56.26", "8.20.247.20", "185.228.168.9", "185.228.169.9",
    "76.76.19.19", "76.223.122.150", "94.140.14.14", "94.140.15.15",
];

#[derive(Debug, Clone)]
struct Options {
    threads: usize,
    resolver_ip: Option<String>,
    resolver_file: Option<String>,
    use_default: bool,
    protocol: String,
    port: u16,
    domain: bool,
}

fn main() {
    let matches = Command::new("dns_resolver")
        .arg(Arg::new("threads")
            .short('t')
            .long("threads")
            .default_value("8")
            .value_parser(value_parser!(usize))
            .help("How many threads should be used"))
        .arg(Arg::new("resolver")
            .short('r')
            .long("resolver")
            .help("IP of the DNS resolver to use for lookups"))
        .arg(Arg::new("resolvers-file")
            .short('R')
            .long("resolvers-file")
            .help("File containing list of DNS resolvers to use for lookups"))
        .arg(Arg::new("use-default")
            .short('U')
            .long("use-default")
            .action(ArgAction::SetTrue)
            .help("Use default resolvers for lookups"))
        .arg(Arg::new("protocol")
            .short('P')
            .long("protocol")
            .default_value("udp")
            .value_parser(["tcp", "udp"])
            .help("Protocol to use for lookups"))
        .arg(Arg::new("port")
            .short('p')
            .long("port")
            .default_value("53")
            .value_parser(value_parser!(u16))
            .help("Port to bother the specified DNS resolver on"))
        .arg(Arg::new("domain")
            .short('d')
            .long("domain")
            .action(ArgAction::SetTrue)
            .help("Output only domains"))
        .get_matches();

    let options = Options {
        threads: *matches.get_one::<usize>("threads").unwrap(),
        resolver_ip: matches.get_one::<String>("resolver").cloned(),
        resolver_file: matches.get_one::<String>("resolvers-file").cloned(),
        use_default: matches.get_flag("use-default"),
        protocol: matches.get_one::<String>("protocol").unwrap().clone(),
        port: *matches.get_one::<u16>("port").unwrap(),
        domain: matches.get_flag("domain"),
    };

    let mut resolvers = Vec::new();

    // Load resolvers from file if specified
    if let Some(resolver_file) = &options.resolver_file {
        match File::open(resolver_file) {
            Ok(file) => {
                let reader = BufReader::new(file);
                for line in reader.lines() {
                    if let Ok(line) = line {
                        resolvers.push(line);
                    }
                }
            }
            Err(err) => {
                eprintln!("Failed to open resolvers file: {}", err);
                process::exit(1);
            }
        }
    }

    // Add single resolver if specified
    if let Some(resolver_ip) = &options.resolver_ip {
        resolvers.push(resolver_ip.clone());
    }

    // Add default resolvers if requested
    if options.use_default {
        resolvers.extend(DEFAULT_RESOLVERS.iter().map(|&r| r.to_string()));
    }

    // If no resolvers were specified, use the first default resolver
    if resolvers.is_empty() {
        resolvers.push(DEFAULT_RESOLVERS[0].to_string());
    }

    // Set up work channel
    let (tx, rx) = std::sync::mpsc::channel();
    let rx = Arc::new(Mutex::new(rx));

    // Start worker threads
    let mut handles = Vec::new();
    for _ in 0..options.threads {
        let rx_clone = Arc::clone(&rx);
        let resolvers_clone = resolvers.clone();
        let options_clone = options.clone();

        let handle = thread::spawn(move || {
            do_work(rx_clone, resolvers_clone, options_clone);
        });
        handles.push(handle);
    }

    // Read IPs from stdin and send to workers
    let stdin = io::stdin();
    let mut stdin_reader = stdin.lock();
    let mut line = String::new();
    while stdin_reader.read_line(&mut line).unwrap() > 0 {
        tx.send(line.trim().to_string()).unwrap();
        line.clear();
    }
    drop(tx); // Close channel to signal threads that there's no more work

    // Wait for all threads to finish
    for handle in handles {
        handle.join().unwrap();
    }
}

fn do_work(rx: Arc<Mutex<std::sync::mpsc::Receiver<String>>>, resolvers: Vec<String>, options: Options) {
    loop {
        let ip = match rx.lock().unwrap().recv() {
            Ok(ip) => ip,
            Err(_) => break, // Channel closed, no more work
        };

        let mut resolved = false;

        // Try each resolver until we get a result
        for resolver in &resolvers {
            if let Some(ptr_records) = lookup_ptr(&ip, resolver, &options) {
                for hostname in ptr_records {
                    if options.domain {
                        // Remove trailing dot from hostname
                        let hostname = hostname.trim_end_matches('.');
                        println!("{}", hostname);
                    } else {
                        println!("{}\t{}", ip, hostname);
                    }
                }
                resolved = true;
                break;
            }
        }

        // Uncomment to see unresolved IPs
        // if !resolved {
        //     eprintln!("Failed to resolve IP: {}", ip);
        // }
    }
}

fn lookup_ptr(ip: &str, resolver: &str, options: &Options) -> Option<Vec<String>> {
    let ip_addr = match IpAddr::from_str(ip) {
        Ok(addr) => addr,
        Err(_) => return None,
    };

    // Create reverse lookup name (PTR format)
    let arpa_name = match ip_addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa.", 
                    octets[3], octets[2], octets[1], octets[0])
        },
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            let mut name = String::new();
            for segment in segments.iter().rev() {
                for i in 0..4 {
                    name.push_str(&format!("{:x}.", (segment >> (4 * i)) & 0xf));
                }
            }
            name.push_str("ip6.arpa.");
            name
        },
    };

    let name = match Name::from_str(&arpa_name) {
        Ok(name) => name,
        Err(_) => return None,
    };

    // Set up the client connection based on protocol
    let socket_addr = match format!("{}:{}", resolver, options.port).to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr,
            None => return None,
        },
        Err(_) => return None,
    };

    let response = match options.protocol.as_str() {
        "udp" => {
            match UdpClientConnection::new(socket_addr) {
                Ok(conn) => {
                    let client = SyncClient::new(conn);
                    match client.query(&name, DNSClass::IN, RecordType::PTR) {
                        Ok(response) => response,
                        Err(_) => return None,
                    }
                },
                Err(_) => return None,
            }
        },
        "tcp" => {
            match TcpClientConnection::new(socket_addr) {
                Ok(conn) => {
                    let client = SyncClient::new(conn);
                    match client.query(&name, DNSClass::IN, RecordType::PTR) {
                        Ok(response) => response,
                        Err(_) => return None,
                    }
                },
                Err(_) => return None,
            }
        },
        _ => return None,
    };

    let answers = response.answers();
    if answers.is_empty() {
        return None;
    }

    let mut results = Vec::new();
    for record in answers {
        if let Some(data) = record.data() {
            if let Some(ptr) = data.as_ptr() {
                results.push(ptr.to_string());
            }
        }
    }

    if results.is_empty() {
        None
    } else {
        Some(results)
    }
}
