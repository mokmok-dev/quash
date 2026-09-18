{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.quash;

  listenPort = lib.toInt (lib.last (lib.splitString ":" cfg.listen));
in
{
  options.services.quash = {
    enable = lib.mkEnableOption "quash, a QUIC transport for SSH";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.quash;
      defaultText = lib.literalExpression "pkgs.quash";
      description = ''
        The quash package to use. The quash overlay provides `pkgs.quash`.
      '';
    };

    listen = lib.mkOption {
      type = lib.types.str;
      default = "0.0.0.0:4433";
      description = "Address and UDP port the QUIC server listens on.";
    };

    proxyTo = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1:22";
      description = "Local sshd address the QUIC server forwards to.";
    };

    certDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/quash";
      description = ''
        Directory that holds the server certificate and key. The private key
        stays readable only by the service user, while the certificate is
        world readable so that clients can bootstrap the fingerprint over SSH.
      '';
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "quash";
      description = "User that runs the quash server.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "quash";
      description = "Group that runs the quash server.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Whether to open the QUIC UDP port in the firewall.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = listenPort > 0;
        message = "services.quash.listen must contain a numeric UDP port.";
      }
    ];

    users.users.${cfg.user} = {
      isSystemUser = true;
      inherit (cfg) group;
      home = cfg.certDir;
    };

    users.groups.${cfg.group} = { };

    environment.systemPackages = [ cfg.package ];

    # Let any logged-in user resolve the fingerprint with
    # `quash server --print-fingerprint` without extra flags.
    environment.variables.QUASH_CERT_DIR = cfg.certDir;

    systemd.services.quash = {
      description = "quash QUIC transport for SSH";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig = {
        ExecStart = lib.escapeShellArgs [
          (lib.getExe cfg.package)
          "server"
          "--listen"
          cfg.listen
          "--proxy-to"
          cfg.proxyTo
          "--cert-dir"
          cfg.certDir
        ];
        User = cfg.user;
        Group = cfg.group;
        StateDirectory = "quash";
        StateDirectoryMode = "0755";
        Restart = "on-failure";
        RestartSec = 5;
        # The service only needs to read and write its own certificate.
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        ReadWritePaths = [ cfg.certDir ];
      };
    };

    networking.firewall.allowedUDPPorts = lib.mkIf cfg.openFirewall [ listenPort ];
  };
}
