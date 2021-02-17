extern crate clap;
extern crate syslog;

use std::collections::HashMap;
use std::str::FromStr;
use std::io;

use std::sync::mpsc;
use std::sync::mpsc::Receiver;
use std::sync::mpsc::TryRecvError;

use std::{thread, time};

use regex::Regex;

use clap::{Arg, App};
use syslog::{Facility,Formatter3164,Logger,LogFormat,Severity};

pub type StructuredData = HashMap<String, HashMap<String, String>>;


fn str_to_severity(s: &str) -> Result<Severity, ()> {
    let result = match &s.to_lowercase()[..] {
        "log_emerg"   | "emerg"   => Severity::LOG_EMERG,
        "log_alert"   | "alert"   => Severity::LOG_ALERT,
        "log_crit"    | "crit"    => Severity::LOG_CRIT,
        "log_err"     | "err"     => Severity::LOG_ERR,
        "log_warning" | "warning" => Severity::LOG_WARNING,
        "log_notice"  | "notice"  => Severity::LOG_NOTICE,
        "log_info"    | "info"    => Severity::LOG_INFO,
        "log_debug"   | "debug"   => Severity::LOG_DEBUG,
        _ => return Err(())
    };
    Ok(result)
}

fn spawn_stdin_channel() -> Receiver<String> {
    let (tx, rx) = mpsc::channel::<String>();
    thread::spawn(move || loop {
        let mut buffer = String::new();
        match io::stdin().read_line(&mut buffer) {
            Ok(_) => {},
            Err(err) => println!("{}", err)
        }

        if buffer.len() == 0 {
            break;
        }

        match tx.send(buffer) {
            Ok(_) => {},
            Err(err) => {
                println!("{}", err);
                break;
            }
        }
    });

    rx
}

use std::io::Write;

fn sleep(millis: u64) {
    let duration = time::Duration::from_millis(millis);
    thread::sleep(duration);
}

fn flush<W, F>(writer: &mut Logger<W, F>, severity: Severity, size: usize, debug: bool, buffer: &mut Vec<String>)
where
  W: Write,
  F: LogFormat<String>
{
    let mut message = buffer.iter().fold(String::new(), |mut s, v| {
        s.push_str(v);
        s
    });

    message.truncate(size);

    if debug {
        println!("[{}]", message.trim_end());
    }

    let res = match severity {
        Severity::LOG_EMERG   => writer.emerg(message),
        Severity::LOG_ALERT   => writer.alert(message),
        Severity::LOG_CRIT    => writer.crit(message),
        Severity::LOG_ERR     => writer.err(message),
        Severity::LOG_WARNING => writer.warning(message),
        Severity::LOG_NOTICE  => writer.notice(message),
        Severity::LOG_INFO    => writer.info(message),
        Severity::LOG_DEBUG   => writer.debug(message)
    };

    match res {
        Ok(_) => {},
        Err(err) => {
            eprintln!("Err: {}", err);
        }
    }

    buffer.clear();
}

fn main() {
    let stdin_channel = spawn_stdin_channel();
    let re_continue = Regex::new(r"^(\s+|Caused by: |Exception was:|--- End of stack trace)").unwrap();

    let matches = App::new("Log Rebuilder")
                          .version("1.0")
                          .author("Patrick MARIE <pm@mkz.me>")
                          .about("Rebuild logs to multi-line records")
                          .arg(Arg::with_name("app_name")
                               .short("a")
                               .long("app_name")
                               .help("Application name (tag)")
                               .takes_value(true))
                          .arg(Arg::with_name("facility")
                               .short("f")
                               .long("facility")
                               .help("Log facility")
                               .takes_value(true))
                          .arg(Arg::with_name("level")
                               .short("l")
                               .long("level")
                               .help("Log level")
                               .takes_value(true))
                          .arg(Arg::with_name("socket_path")
                               .short("S")
                               .long("socket_path")
                               .help("Socket path")
                               .takes_value(true))
                          .arg(Arg::with_name("message_size")
                               .short("s")
                               .long("message_size")
                               .help("Max message size")
                               .takes_value(true))
                          .arg(Arg::with_name("debug")
                               .short("d")
                               .long("debug")
                               .help("Send messages to stdout as well"))
                          .get_matches();

    let app_name = matches.value_of("app_name").unwrap_or("missing_app_name");
    let facility = matches.value_of("facility").unwrap_or("local5");
    let socket_path = matches.value_of("socket_path").unwrap_or("/dev/log");
    let severity = matches.value_of("level").unwrap_or("info");
    let message_size = matches.value_of("message_size").unwrap_or("8000");
    let debug = matches.is_present("debug");

    let facility = match Facility::from_str(&facility) {
        Ok(f) => f,
        Err(_) => {
            eprintln!("Invalid facility: \"{}\".", facility);
            return;
        }
    };

    let severity = match str_to_severity(&severity) {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Invalid severity: \"{}\".", severity);
            return;
        }
    };

    let message_size = match message_size.parse::<usize>() {
        Ok(m) => m,
        Err(_) => {
            eprintln!("Invalid message size: \"{}\".", message_size);
            return;
        }
    };

    let formatter = Formatter3164 {
        facility: facility,
        hostname: None,
        process: app_name.into(),
        pid: 0,
    };

    let mut writer = match syslog::unix_custom(formatter, socket_path) {
        Err(e) => {
            eprintln!("Impossible to connect to syslog: {:?}", e);
            return;
        },
        Ok(writer) => {
            writer
        }
    };

    let mut buffer : Vec<String> = vec![];

    loop {
        match stdin_channel.try_recv() {
            Ok(line) => {
                if re_continue.is_match(&line) {
                    buffer.push(String::from(line));
                } else if buffer.len() > 0 {
                    flush(&mut writer, severity, message_size, debug, &mut buffer);
                    buffer.push(String::from(line));
                } else {
                    buffer.push(String::from(line));
                }
            },
            Err(TryRecvError::Empty) => {
                // no more log: flush logs
                if buffer.len() > 0 {
                    flush(&mut writer, severity, message_size, debug,&mut buffer);
                }
                
                sleep(200);
            },
            Err(TryRecvError::Disconnected) => {
                break;
            },
        }
    }
}
