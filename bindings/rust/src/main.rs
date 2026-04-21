mod primitives;
mod protocol;

fn main() {
    println!("── Primitives smoke tests ──────────────────────────────────");
    primitives::run_all();

    println!();
    println!("── Protocol smoke tests ────────────────────────────────────");
    protocol::run_all();

    println!();
    println!("All smoke tests passed.");
}
