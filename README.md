# log-rebuilder

This tool takes as an input a log file, and forwards logs to local syslog after trying to rebuild multiple lines messages, as stacktraces, as single message.

## Usage

```sh
$ cargo run -- --help
Log Rebuilder 1.0
Patrick MARIE <pm@mkz.me>
Rebuild logs to multi-line records

USAGE:
    log-rebuilder [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -a, --app_name <app_name>            Application name (tag)
    -f, --facility <facility>            Log facility
    -l, --level <level>                  Log level
    -s, --message_size <message_size>    Max message size
    -S, --socket_path <socket_path>      Socket path

$ tail -f stdout | cargo run -a my_application -l info -f level5 -s 1024
```

## Pattern