{
  inputs = {
    nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0";
    flake-parts.url = "https://flakehub.com/f/hercules-ci/flake-parts/0";
    flake-parts.inputs.nixpkgs-lib.follows = "nixpkgs";
    git-hooks.url = "https://flakehub.com/f/cachix/git-hooks.nix/0";
    git-hooks.inputs.nixpkgs.follows = "nixpkgs";
    treefmt-nix.url = "https://flakehub.com/f/numtide/treefmt-nix/0";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
    rust-overlay.url = "https://flakehub.com/f/oxalica/rust-overlay/0";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
    crane.url = "https://flakehub.com/f/ipetkov/crane/0";
  };

  outputs =
    {
      nixpkgs,
      flake-parts,
      git-hooks,
      treefmt-nix,
      rust-overlay,
      crane,
      ...
    }@inputs:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        git-hooks.flakeModule
        treefmt-nix.flakeModule
      ];

      flake = {
        overlays.default = final: _prev: {
          quash = inputs.self.packages.${final.stdenv.hostPlatform.system}.default;
        };

        nixosModules.default = import ./nix/module.nix;
        nixosModules.quash = import ./nix/module.nix;
        homeManagerModules.default = import ./nix/hm-module.nix;
        homeManagerModules.quash = import ./nix/hm-module.nix;
      };

      perSystem =
        { pkgs, system, ... }:
        let
          rustToolchain = pkgs.rust-bin.stable.latest.default;
          src = pkgs.lib.cleanSourceWith { src = ./.; };
          craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;
          commonArgs = {
            inherit src;
            strictDeps = true;
          };
          cargoArtifacts = craneLib.buildDepsOnly commonArgs;
        in
        {
          _module.args = {
            pkgs = import nixpkgs {
              inherit system;
              overlays = [ rust-overlay.overlays.default ];
            };
          };

          packages.default = craneLib.buildPackage (
            commonArgs
            // {
              inherit cargoArtifacts;
              meta.mainProgram = "quash";
            }
          );

          checks = {
            clippy = craneLib.cargoClippy (
              commonArgs
              // {
                inherit
                  src
                  cargoArtifacts
                  ;
                cargoClippyExtraArgs = "--all-targets --all-features -- --deny warnings";
              }
            );
            test = craneLib.cargoTest (
              commonArgs
              // {
                inherit
                  src
                  cargoArtifacts
                  ;
              }
            );
          };

          devShells.default = pkgs.mkShellNoCC {
            inputsFrom = [ git-hooks.devShells ];
            buildInputs = with pkgs; [ sccache ];
            packages =
              with pkgs;
              [
                rustToolchain
              ]
              ++ pkgs.lib.optionals pkgs.stdenv.hostPlatform.isLinux [ mold ];

            shellHook = ''
              export RUSTC_WRAPPER="${pkgs.lib.getExe pkgs.sccache}"
              ${pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isLinux ''
                export RUSTFLAGS="''${RUSTFLAGS:-} -C link-arg=-fuse-ld=mold"
              ''}
            '';
          };

          pre-commit.settings = {
            hooks = {
              deadnix.enable = true;
              statix.enable = true;
            };
          };

          treefmt = {
            projectRootFile = "flake.nix";
            programs = {
              nixfmt.enable = true;
              rustfmt.enable = true;
              rustfmt.package = rustToolchain;
              taplo.enable = true;
              yamlfmt.enable = true;
            };
          };

        };

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
    };
}
