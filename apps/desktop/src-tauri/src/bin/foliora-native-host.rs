fn main() {
    if let Err(error) = foliora_desktop::native_host::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
