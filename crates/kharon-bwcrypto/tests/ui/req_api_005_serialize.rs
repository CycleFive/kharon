use kharon_bwcrypto::Secret;

fn main() {
    let s = Secret::new(String::from("canary"));
    let _ = serde_json::to_string(&s);
}
