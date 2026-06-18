fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().unwrap();
    prost_build::Config::new()
        .protoc_executable(protoc)
        .compile_protos(&["proto/privacy_coin.proto"], &["proto"])
        .unwrap();
}
