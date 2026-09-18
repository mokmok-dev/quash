{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.programs.quash;

  mkProxyCommand =
    host:
    let
      args = [
        (lib.getExe cfg.package)
        "client"
        "--remote"
        host.remote
        "--ssh-target"
        host.sshTarget
      ]
      ++ lib.optionals (host.serverName != null) [
        "--server-name"
        host.serverName
      ]
      ++ lib.optionals (host.sshPort != 22) [
        "--ssh-port"
        (toString host.sshPort)
      ]
      ++ lib.optionals (host.bootstrapCommand != null) [
        "--bootstrap-command"
        host.bootstrapCommand
      ]
      ++ lib.optionals (host.fingerprint != null) [
        "--fingerprint"
        host.fingerprint
      ];
    in
    lib.concatMapStringsSep " " lib.escapeShellArg args;
in
{
  options.programs.quash = {
    enable = lib.mkEnableOption "quash SSH ProxyCommand integration";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.quash;
      defaultText = lib.literalExpression "pkgs.quash";
      description = ''
        The quash package to use. The quash overlay provides `pkgs.quash`.
      '';
    };

    hosts = lib.mkOption {
      type = lib.types.attrsOf (
        lib.types.submodule {
          options = {
            remote = lib.mkOption {
              type = lib.types.str;
              example = "192.0.2.10:4433";
              description = "QUIC server address.";
            };

            sshTarget = lib.mkOption {
              type = lib.types.str;
              example = "user@192.0.2.10";
              description = "SSH target used to bootstrap the certificate fingerprint.";
            };

            serverName = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = "TLS server name used for the QUIC handshake.";
            };

            sshPort = lib.mkOption {
              type = lib.types.port;
              default = 22;
              description = "SSH port used for the bootstrap connection.";
            };

            bootstrapCommand = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              example = "quash server --print-fingerprint";
              description = "Command run over SSH to print the server fingerprint.";
            };

            fingerprint = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = ''
                Pinned certificate fingerprint. When set, the SSH bootstrap is
                skipped and this value is used directly.
              '';
            };
          };
        }
      );
      default = { };
      example = {
        "*.ts.net" = {
          remote = "100.75.236.9:4433";
          sshTarget = "user@100.75.236.9";
        };
      };
      description = "Host patterns that should be reached over QUIC.";
    };
  };

  config = lib.mkIf cfg.enable {
    home.packages = [ cfg.package ];

    programs.ssh = {
      enable = lib.mkDefault true;
      settings = lib.mapAttrs (_pattern: host: {
        ProxyCommand = mkProxyCommand host;
      }) cfg.hosts;
    };
  };
}
