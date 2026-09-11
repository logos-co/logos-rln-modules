{
  description = "Logos RLN Module (Rust port of logos-lez-rln-module)";

  nixConfig = {
    extra-substituters = [ "https://cache.nix.logos.co/public" ];
    extra-trusted-public-keys = [
      "public:l4HrXgL4nw246+LBh2SOJyhz64BoGegOYLheT/iIAPU="
    ];
  };

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    # Must match the root flake's pin.
    logos-execution-zone.url = "github:adklempner/logos-execution-zone?rev=8e2b119ea4e18faee58c4c469943cb1beaab742a";
    # Name matches metadata.json#dependencies; the builder resolves by name.
    lez_core = {
      url = "github:logos-blockchain/logos-execution-zone-module?rev=0ea57f8a1c57539d6ee0961a9cd27b064685b9e8";
      inputs.logos-execution-zone.follows = "logos-execution-zone";
    };
  };

  outputs = inputs@{ self, logos-module-builder, ... }:
    let
      nixpkgs = logos-module-builder.inputs.nixpkgs;
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAllSystems = fn: nixpkgs.lib.genAttrs systems fn;

      # The builder runs logos-lidl-gen to emit the C ABI scaffold (+ the
      # typed lez_core dependency client) at rust-lib/generated/,
      # compiles the staticlib, and wraps it in the Qt cdylib glue, driven by
      # metadata.json — including concurrency:"multi" (see README "Design
      # constraints").
      #
      # RISC0_SKIP_BUILD_KERNELS comes from metadata nix.rust.env: risc0-zkvm
      # is serde-only here, no proving.
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
          liblogos_lez_rln_module = m.default;
        });

      # The builder walks a dependency's config + inputs to bundle the chain.
      inherit (module) config;

      # `nix run .#generate` materialises the two gitignored inputs rust-lib/
      # references: the provider scaffold at rust-lib/generated/ and the SDK
      # source the crate path-deps as `../logos-rust-sdk-src`. Both come from
      # the builder this flake locks, so they cannot drift from what the nix
      # build compiles. After it, bare `cargo build/test/clippy` works in
      # rust-lib/.
      apps = forAllSystems (system:
        let
          pkgs = import nixpkgs { inherit system; };
          lidlGen = logos-module-builder.inputs.logos-rust-sdk.packages.${system}.lidl-gen;
          sdkSrc = logos-module-builder.packages.${system}.rust-sdk-src;
          # The protocol version the builder stamps into the module (and gates
          # the module-impl exports on), read the same way mkLogosModule reads
          # it: LOGOS_PROTOCOL_VERSION_STRING of the builder's logos-protocol
          # input. Without it lidl-gen defaults to 0.1.0 and the local scaffold
          # would carry fewer exports than the nix build compiles.
          protocolVersion =
            let
              header = builtins.readFile
                "${logos-module-builder.inputs.logos-protocol}/cpp/logos_protocol.h";
              parts = builtins.split "LOGOS_PROTOCOL_VERSION_STRING \"([^\"]*)\"" header;
            in
            if builtins.length parts < 2
            then throw "logos-protocol header carries no LOGOS_PROTOCOL_VERSION_STRING"
            else builtins.head (builtins.elemAt parts 1);
          generate = pkgs.writeShellApplication {
            name = "lez-rln-module-generate";
            runtimeInputs = [ lidlGen pkgs.gitMinimal ];
            text = ''
              # Optional argument: the module dir — for a staged copy of the
              # tree that carries no .git (the e2e harness materialises one).
              root="''${1:-$(git rev-parse --show-toplevel)/logos-lez-rln-module}"
              echo "generating rust-lib/generated/provider_gen.rs (protocol ${protocolVersion}) ..."
              mkdir -p "$root/rust-lib/generated"
              logos-lidl-gen "$root/rust-lib/liblogos_lez_rln_module.lidl" --provider \
                --concurrency multi \
                --protocol-version ${protocolVersion} \
                --dep lez_core="$root/rust-lib/deps/lez_core.lidl" \
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
            program = "${generate}/bin/lez-rln-module-generate";
          };
        });
    };
}
