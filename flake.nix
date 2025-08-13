{
  description = "zig-uuid";

  inputs = {
    nixpkgs = {
      url = "nixpkgs/nixos-unstable";
    };
    flake-utils = {
      url = "github:numtide/flake-utils";
    };
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
    zig = {
      url = "github:mitchellh/zig-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
        flake-utils.follows = "flake-utils";
        flake-compat.follows = "flake-compat";
      };
    };
  };

  outputs = {
    nixpkgs,
    flake-utils,
    zig,
    ...
  }: let
  in
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs {
          inherit system;
        };
      in {
        devShells = {
          zig_0_14 = pkgs.mkShell {
            name = "zig-uuid-0.14";
            nativeBuildInputs = [
              pkgs.zig_0_14
              pkgs.pinact
            ];
          };
          zig_0_15 = pkgs.mkShell {
            name = "zig-uuid-0.15";
            nativeBuildInputs = [
              zig.packages.${system}.master
              pkgs.pinact
            ];
          };
        };
      }
    );
}
