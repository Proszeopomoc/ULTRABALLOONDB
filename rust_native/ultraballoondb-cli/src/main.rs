fn main() {
    let exit_code = ultraballoondb_cli::main_entry(std::env::args());
    std::process::exit(exit_code);
}
