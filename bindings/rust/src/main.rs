mod primitives;
mod protocol;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    println!("── Primitives smoke tests ──────────────────────────────────");
    primitives::run_all();

    println!();
    println!("── Protocol smoke tests ────────────────────────────────────");
    protocol::run_all().await;

    println!();
    println!("All smoke tests passed.");
}
