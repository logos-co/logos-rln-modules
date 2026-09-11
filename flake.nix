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

    # v0.2.5-rc2 plus one commit: the wallet takes its execution gas limit from
    # config instead of a 2,000,000 constant. Gas is cycles in v0.2.5, so that
    # constant is a ceiling on how expensive a program a module may call, and a
    # registration needs about nine million. Nothing on the path from a module
    # into the wallet carries a gas argument, so config is the only way to
    # raise it. Drop this the moment it lands upstream.
    logos-execution-zone.url = "github:adklempner/logos-execution-zone?rev=fc36c8ebc9af584bc5e70c8c4f97655bac9e145b";

    logos-wallet-module = {
      url = "github:logos-blockchain/logos-execution-zone-module?rev=0ea57f8a1c57539d6ee0961a9cd27b064685b9e8";
      inputs.logos-execution-zone.follows = "logos-execution-zone";
    };

    logos-module-viewer.url = "github:logos-co/logos-module-viewer";

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

          lezRlnModule = logos-lez-rln-module.packages.${system};
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
