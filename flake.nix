{
    description = "Dev environment with cassandra";

    inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";

    outputs = { self, nixpkgs, ... }: {
        devShells.x86_64-linux.default =
            let
                pkgs = import nixpkgs {
                    system = "x86_64-linux";
                    config.allowUnfree = true;
                };
            in
                pkgs.mkShell {
                    name = "cassandra-dev";

                    nativeBuildInputs = with pkgs; [
                        pkg-config
                        openssl
                        libuv
                        cassandra-cpp-driver
                        sqlite
                    ];

                    packages = with pkgs; [
                        rustup
                        gcc
                        cargo
                        openssl
                        openssl.dev
                        libuv
                        cassandra-cpp-driver
                        pkg-config
                        cmake

                        sqlite
                        #jetbrains.rust-rover
                    ];

                    # Set PKG_CONFIG_PATH from actual locations
                    PKG_CONFIG_PATH = pkgs.lib.makeSearchPath "lib/pkgconfig" [
                        pkgs.openssl
                        pkgs.libuv
                        pkgs.cassandra-cpp-driver
                    ];
                };
    };
}
