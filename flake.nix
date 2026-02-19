{
  description = "OpenCode Security: ACP-compliant security proxy and plugin for OpenCode file access control";

  # ============================================================
  # INPUTS
  # ============================================================

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  # ============================================================
  # OUTPUTS
  # ============================================================

  outputs =
    { self
    , nixpkgs
    , flake-utils
    , ...
    }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];

      forAllSystems = f: nixpkgs.lib.genAttrs supportedSystems (system:
        f {
          inherit system;
          pkgs = import nixpkgs { inherit system; };
        }
      );

    in
    {
      # ── Packages ──────────────────────────────────────────────
      packages = forAllSystems ({ pkgs, system }: let
        python = pkgs.python312;
      in {
        opencode-security-filter = python.pkgs.buildPythonPackage {
          pname = "opencode-security-filter";
          version = "0.1.0";
          pyproject = true;

          src = ./opencode-security-filter;

          build-system = [ python.pkgs.hatchling ];
        };

        default = self.packages.${system}.opencode-security-filter;
      });

      # ── Dev Shell ─────────────────────────────────────────────
      devShells = forAllSystems ({ pkgs, ... }: let
        python = pkgs.python312;
      in {
        default = pkgs.mkShell {
          name = "opencode-security-dev";

          packages = [
            # -- Python tooling --
            (python.withPackages (ps: [ ps.pip ps.virtualenv ps.mypy ]))
            pkgs.uv
            pkgs.ruff

            # -- TypeScript/Bun tooling --
            pkgs.bun
          ];

          buildInputs = [
            pkgs.zlib
            pkgs.stdenv.cc.cc.lib
          ];

          shellHook = ''
            # Activate .venv if present
            if [ -d .venv ]; then
              source .venv/bin/activate
            fi

            # Ensure native libs are findable
            export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [
              pkgs.zlib
              pkgs.stdenv.cc.cc.lib
            ]}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          '';
        };
      });
    };
}
