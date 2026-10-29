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

    # The lez_core wallet module liblogos_lez_rln_module (7.0.0+) drives: 0.5.1,
    # on LEZ v0.3.1 — the release the official catalog publishes, which is
    # where a delivery install gets it. Exported as `wallet-module` for the e2e
    # harness. Its own lock pins LEZ; the stock 2M gas limit covers every
    # registration-program call, so no gas-limit fork is needed any more.
    logos-wallet-module.url = "github:logos-blockchain/logos-execution-zone-module?rev=51a6fee385eedfdc65ba71f01447c5411a54bdf7";

    logos-module-viewer.url = "github:logos-co/logos-module-viewer";

    logos-lez-rln-module.url = "path:./logos-lez-rln-module";
    logos-rln-module.url = "path:./logos-rln-module";
    logos-rln-data-service-module.url = "path:./logos-rln-data-service-module";
  };

  outputs =
    {
      self,
      nixpkgs,
      logos-wallet-module,
      logos-module-viewer,
      logos-lez-rln-module,
      logos-rln-module,
      logos-rln-data-service-module,
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
          dataServiceModule = logos-rln-data-service-module.packages.${system};
        in
        {
          logos-lez-rln-module = lezRlnModule.default;
          logos-lez-rln-module-lgx = lezRlnModule.lgx;
          logos-rln-module = rlnModule.default;
          logos-rln-module-lgx = rlnModule.lgx;
          logos-rln-data-service-module = dataServiceModule.default;
          logos-rln-data-service-module-lgx = dataServiceModule.lgx;
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
          logosRlnDataServiceModuleLib = self.packages.${system}.logos-rln-data-service-module;
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
          inspectRlnDataServiceModule = {
            type = "app";
            program =
              "${pkgs.writeShellScriptBin "inspect-rln-data-service-module" ''
                exec ${logosModuleViewerPackage}/bin/logos-module-viewer \
                  --module ${logosRlnDataServiceModuleLib}/lib/liblogos_rln_data_service_module_plugin.${extension}
              ''}/bin/inspect-rln-data-service-module";
          };
        in
        {
          inspect-lez-rln-module = inspectLezRlnModule;
          inspect-rln-module = inspectRlnModule;
          inspect-rln-data-service-module = inspectRlnDataServiceModule;
          default = inspectRlnModule;
        }
      );
    };
}
