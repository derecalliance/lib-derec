
pub mod derec_proto {
    // OUT_DIR is where the generated code is stored during compilation
    include!(concat!(env!("OUT_DIR"), "/org.derecalliance.derec.protobuf.rs")); // filename matches proto
}

pub fn handle(msg: &crate::derec_proto::ContactMessage) {
    println!("Received message: {:?}", msg);
}