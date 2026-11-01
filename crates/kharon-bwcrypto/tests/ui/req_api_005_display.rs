use kharon_bwcrypto::Secret;

fn main() {
    let s = Secret::new(String::from("canary"));
    let _ = format!("{}", s);
}
