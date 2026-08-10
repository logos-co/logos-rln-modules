{
  description = "Logos RLN Modules";

  inputs = {
    nixpkgs.follows = "logos-core/nixpkgs";

    logos-core.url = "github:logos-co/logos-cpp-sdk/25c88f4d48fa95ea4437194bcf60bd8d0cf84a74";

    logos-execution-zone.url = "github:logos-blockchain/logos-execution-zone?rev=e37876a64028a335eb693198a1ed6a0e875ec5b4";

    logos-wallet-module = {
      url = "github:logos-blockchain/logos-execution-zone-module?rev=d70225ced646934d2294fd9e8f8b03615c104b80";
      inputs.logos-execution-zone.follows = "logos-execution-zone";
    };

    logos-module-viewer.url = "github:logos-co/logos-module-viewer";

    # Path inputs: each one's logos-module-builder closure inlines into
    # flake.lock (roughly doubling it per module). Deliberately no nested
    # `follows` — the duplicated nixpkgs nodes already lock our same rev, the
    # builder pins its own rust-overlay/toolchain, and dedup is only
    # reachable upstream in the builder.
    logos-lez-rln-module.url = "path:./logos-lez-rln-module";
    logos-rln-module.url = "path:./logos-rln-module";
  };

  outputs =
    {
      self,
      nixpkgs,
      logos-wallet-module,
      logos-module-viewer,
      logos-lez-rln-module,
      logos-rln-module,
      ...
    }:
    let
      lib = nixpkgs.lib;

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
        "x86_64-darwin"
      ];

      forAll = lib.genAttrs systems;
    in
    {
      packages = forAll (
        system:
        let
          walletModulePackage = logos-wallet-module.packages.${system}.lgx;

          # The sim overrides this input with a local `path:` tree at build
          # time (`--override-input logos-lez-rln-module path:...`) so its
          # gitignored staged source — logos-rust-sdk-src — is visible; the
          # default `path:./logos-lez-rln-module` covers in-tree builds.
          lezRlnModule = logos-lez-rln-module.packages.${system};

          # The main RLN module (RLN-MEMBERSHIP-MANAGEMENT spec); same
          # staged-sources caveat as the LEZ RLN module — refresh its
          # logos-rust-sdk-src via `nix run ./logos-rln-module#generate`.
          rlnModule = logos-rln-module.packages.${system};
        in
        {
          logos-lez-rln-module = lezRlnModule.default;
          logos-lez-rln-module-lgx = lezRlnModule.lgx;
          logos-rln-module = rlnModule.default;
          logos-rln-module-lgx = rlnModule.lgx;
          wallet-module = walletModulePackage;
          default = rlnModule.lgx;
        }
      );

      apps = forAll (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          logosLezRlnModuleLib = self.packages.${system}.logos-lez-rln-module;
          logosRlnModuleLib = self.packages.${system}.logos-rln-module;
          logosModuleViewerPackage = logos-module-viewer.packages.${system}.default;
          extension = if pkgs.stdenv.isDarwin then "dylib" else "so";
          inspectLezRlnModule = {
            type = "app";
            program =
              "${pkgs.writeShellScriptBin "inspect-lez-rln-module" ''
                exec ${logosModuleViewerPackage}/bin/logos-module-viewer \
                  --module ${logosLezRlnModuleLib}/lib/liblogos_lez_rln_module_plugin.${extension}
              ''}/bin/inspect-lez-rln-module";
          };
          inspectRlnModule = {
            type = "app";
            program =
              "${pkgs.writeShellScriptBin "inspect-rln-module" ''
                exec ${logosModuleViewerPackage}/bin/logos-module-viewer \
                  --module ${logosRlnModuleLib}/lib/liblogos_rln_module_plugin.${extension}
              ''}/bin/inspect-rln-module";
          };
        in
        {
          inspect-lez-rln-module = inspectLezRlnModule;
          inspect-rln-module = inspectRlnModule;
          default = inspectRlnModule;
        }
      );
    };
}
