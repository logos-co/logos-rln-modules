{
  description = "Logos RLN Modules";

  nixConfig = {
    extra-substituters = [ "https://cache.nix.logos.co/public" ];
    extra-trusted-public-keys = [
      "public:l4HrXgL4nw246+LBh2SOJyhz64BoGegOYLheT/iIAPU="
    ];
  };

  inputs = {
    nixpkgs.follows = "logos-core/nixpkgs";

    logos-core.url = "github:logos-co/logos-cpp-sdk/25c88f4d48fa95ea4437194bcf60bd8d0cf84a74";

    # lez v0.2.5-rc2. PR #669 renamed PrivateKeyHolder's nullifier_secret_key
    # to a derived authorization_secret_key, so a storage.json written by an
    # earlier lez is rejected: regenerate the seed wallet against this tag.
    logos-execution-zone.url = "github:logos-blockchain/logos-execution-zone?rev=d8596eb734bf9c9ce801afb92df06098a2eb098a";

    # Moves with logos-execution-zone, which it `follows`: the rev below is the
    # first that builds against the renamed key schema.
    logos-wallet-module = {
      url = "github:logos-blockchain/logos-execution-zone-module?rev=0ea57f8a1c57539d6ee0961a9cd27b064685b9e8";
      inputs.logos-execution-zone.follows = "logos-execution-zone";
    };

    logos-module-viewer.url = "github:logos-co/logos-module-viewer";

    # Deliberately no nested `follows` on these path inputs: the builder pins
    # its own rust-overlay/toolchain and the duplicated nixpkgs nodes already
    # lock the same rev.
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

          # The sim builds with `--override-input logos-lez-rln-module
          # path:...` so the gitignored staged logos-rust-sdk-src is visible;
          # the default covers in-tree builds.
          lezRlnModule = logos-lez-rln-module.packages.${system};

          # The main RLN module (RLN-MEMBERSHIP-MANAGEMENT spec); refresh its
          # gitignored logos-rust-sdk-src via `nix run ./logos-rln-module#generate`.
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
