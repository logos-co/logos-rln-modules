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

      # The builder runs logos-lidl-gen to emit the module-impl C ABI scaffold
      # (+ the typed logos_execution_zone dependency client) at
      # rust-lib/generated/, compiles the staticlib, and wraps it in the Qt
      # cdylib glue — all driven by metadata.json (codegen.rust +
      # dependency_overrides; concurrency stays at the single default until
      # the delivery module's logos-cpp-sdk pin learns the deferred-result
      # sentinel — see README "Design constraints").
      #
      # The RLN core lives in-crate at rust-lib/src/rln_core.rs; the only
      # path-dep is the shared rln-layouts crate, staged at
      # rust-lib/lez-rln-src/rln-layouts (a copy of ../lez-rln/rln-layouts):
      # mkLogosModule's rustCrateSrc stages ONLY the crate dir (plus
      # logos-rust-sdk-src) into the sandbox, so path-deps must live inside
      # rust-lib/ to survive the builder's vendoring.
      #
      # No lssa crates are in the tree (rln-layouts is borsh-only), so no
      # circuits/rapidsnark rustEnv pins and no pyo3 are needed.
      # RISC0_SKIP_BUILD_KERNELS comes from metadata nix.rust.env
      # (risc0-zkvm is serde-only here; no proving).
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
