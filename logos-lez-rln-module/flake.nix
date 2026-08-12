{
  description = "Logos RLN Module (Rust port of logos-lez-rln-module)";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
  };

  outputs = inputs@{ self, logos-module-builder, ... }:
    let
      nixpkgs = logos-module-builder.inputs.nixpkgs;
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      forAllSystems = fn: nixpkgs.lib.genAttrs systems fn;

      # The builder runs logos-lidl-gen to emit the C ABI scaffold (+ the
      # typed logos_execution_zone dependency client) at rust-lib/generated/,
      # compiles the staticlib, and wraps it in the Qt cdylib glue, driven by
      # metadata.json. Concurrency stays at the single default (see README
      # "Design constraints").
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
    };
}
