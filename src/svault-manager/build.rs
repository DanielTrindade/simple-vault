fn main() {
    println!("cargo:rerun-if-changed=ui/icons/app.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new()
            .set_icon("ui/icons/app.ico")
            .set("ProductName", "SVault")
            .set("FileDescription", "SVault Manager")
            .compile()
            .expect("falha ao incorporar o ícone do aplicativo");
    }
    let config = slint_build::CompilerConfiguration::new().with_style("fluent-dark".into());
    slint_build::compile_with_config("ui/app.slint", config)
        .expect("falha ao compilar a interface Slint");
}
