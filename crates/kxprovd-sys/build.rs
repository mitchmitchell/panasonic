fn main() {
    println!("cargo::rustc-check-cfg=cfg(kxprovd_sys_has_tiocmget)");
    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-cfg=kxprovd_sys_has_tiocmget");
    }
}
