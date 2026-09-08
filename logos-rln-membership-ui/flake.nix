{
  description = "RLN Membership Management GUI (ui_qml module: register + view memberships)";

  nixConfig = {
    extra-substituters = [ "https://cache.nix.logos.co/public" ];
    extra-trusted-public-keys = [
      "public:l4HrXgL4nw246+LBh2SOJyhz64BoGegOYLheT/iIAPU="
    ];
  };

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
  };

  # QML-only ui_qml module (no C++ backend): mkLogosQmlModule packages the
  # QML view + metadata.json, provides `nix run .` (mounts the view in the
  # bundled logos-standalone-app), `.#lgx` (the installable bundle basecamp's
  # package manager consumes), and auto-wires tests/*.mjs as `.#integration-test`.
  # All backend access goes through the host-injected `logos` bridge — the
  # design-system QML modules (Logos.Theme / Logos.Controls) are provided by
  # the host app and deliberately NOT bundled here.
  outputs =
    inputs@{ logos-module-builder, ... }:
    logos-module-builder.lib.mkLogosQmlModule {
      src = ./.;
      configFile = ./metadata.json;
      flakeInputs = inputs;
    };
}
