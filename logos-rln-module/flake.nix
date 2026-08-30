{
  description = "Logos RLN Membership Management Module";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
  };

  outputs = inputs@{ self, logos-module-builder, ... }:
    let
      nixpkgs = logos-module-builder.inputs.nixpkgs;
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAllSystems = fn: nixpkgs.lib.genAttrs systems fn;

      # The builder runs logos-lidl-gen to emit the C ABI scaffold (+ the
      # typed liblogos_lez_rln_module dependency client) at rust-lib/generated/,
      # compiles the staticlib, and wraps it in the Qt cdylib glue, driven by
      # metadata.json. Concurrency stays at the single default: the register
      # path is fire-and-record (lp_invoke_async), so no handler blocks on a
      # sequencer submit.
      module = logos-module-builder.lib.mkLogosModule {
        src = ./.;
        configFile = ./metadata.json;
        flakeInputs = inputs;
      };
    in
    {
      packages = forAllSystems (system:
        let m = module.packages.${system};
        in m // {
          liblogos_rln_module = m.default;
        });

      # `nix run .#generate` materialises the two gitignored inputs rust-lib/
      # references: the provider scaffold at rust-lib/generated/ and the SDK
      # source the crate path-deps as `../logos-rust-sdk-src`. After it, bare
      # `cargo build/test/clippy` works in rust-lib/.
      apps = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          lidlGen = logos-module-builder.inputs.logos-rust-sdk.packages.${system}.lidl-gen;
          sdkSrc = logos-module-builder.packages.${system}.rust-sdk-src;
          generate = pkgs.writeShellApplication {
            name = "rln-module-generate";
            runtimeInputs = [ lidlGen pkgs.gitMinimal ];
            text = ''
              root="$(git rev-parse --show-toplevel)/logos-rln-module"
              echo "generating rust-lib/generated/provider_gen.rs ..."
              mkdir -p "$root/rust-lib/generated"
              logos-lidl-gen "$root/rust-lib/liblogos_rln_module.lidl" --provider \
                --concurrency multi \
                --dep liblogos_lez_rln_module="$root/rust-lib/deps/liblogos_lez_rln_module.lidl" \
                -o "$root/rust-lib/generated/provider_gen.rs"
              echo "staging the SDK source at logos-rust-sdk-src/ ..."
              rm -rf "''${root:?}/logos-rust-sdk-src"
              cp -RL "${sdkSrc}" "$root/logos-rust-sdk-src"
              chmod -R u+w "$root/logos-rust-sdk-src"
              echo "done. bare 'cargo build' now works in rust-lib/"
            '';
          };
        in {
          generate = {
            type = "app";
            program = "${generate}/bin/rln-module-generate";
          };
        });
    };
}
