# SPDX-FileCopyrightText: © 2025 Jeffrey C. Ollie
# SPDX-License-Identifier: MIT

{
  description = "zig-uuid";

  inputs = {
    nixpkgs = {
      url = "https://channels.nixos.org/nixpkgs-unstable/nixexprs.tar.xz";
    };
    zon2nix = {
      url = "github:jcollie/zon2nix";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
  };

  outputs =
    {
      nixpkgs,
      ...
    }:
    let
      inherit (nixpkgs) lib;
      makePackages =
        system:
        import nixpkgs {
          inherit system;
        };
      forAllSystems = lib.genAttrs lib.systems.flakeExposed;
    in
    {
      devShells = forAllSystems (
        system:
        let
          pkgs = makePackages system;
        in
        {
          default = pkgs.mkShell {
            nativeBuildInputs = [
              pkgs.git-pages-cli
              pkgs.pinact
              pkgs.reuse
              pkgs.zig_0_16
            ];
          };
        }
      );
    };
}
