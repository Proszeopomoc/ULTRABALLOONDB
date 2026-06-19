fn main() {
    let exit_code = ultraballoondb_trust_asymmetric::main_entry(
        std::env::args(),
    );
    std::process::exit(exit_code);
}
