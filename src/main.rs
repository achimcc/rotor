fn main() {
    let (code, out) = rotor::run(std::env::args().skip(1).collect());
    if code == 2 {
        eprint!("{out}");
    } else {
        print!("{out}");
    }
    std::process::exit(code);
}
