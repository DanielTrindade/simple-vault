fn main() {
    println!("cargo:rerun-if-changed=../svault-manager/ui/icons/app.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new()
            .set_icon("../svault-manager/ui/icons/app.ico")
            .set("ProductName", "SVault")
            .set("FileDescription", "SVault Secret Broker")
            .compile()
            .expect("falha ao incorporar recursos do executavel svault-broker");
    }
}
