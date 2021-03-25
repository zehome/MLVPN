{
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
  };

  outputs = inp:
    let
      lib = inp.nixpkgs.lib;
      systems = [ "aarch64-linux" "armv7l-linux" "x86_64-linux" ];
      
      pkgsForSystem = system: inp.nixpkgs.legacyPackages."${system}";
      pkgsCross = system: crossSystem: import inp.nixpkgs {
        inherit system crossSystem;
      };
      buildFor = pkgs: pkgs.stdenv.mkDerivation {
        src = ./.;
        name = "mlvpn";
        nativeBuildInputs = with pkgs; [
          automake
          autoconf
          pkg-config
        ];
        buildInputs = with pkgs; [
          libev
          libsodium
          libpcap
        ];
        preConfigure = ''
          ./autogen.sh
        '';
      };
    in
      rec {
        defaultPackage = lib.genAttrs systems (system: packages."${system}".mlvpn);
        packages = lib.genAttrs systems (system:
          let 
            otherSystems = builtins.filter (s: s != system) systems;
          in
          {
            mlvpn = buildFor (pkgsForSystem system);
            mlvpn-static = buildFor (pkgsForSystem system).pkgsStatic;
          }

          # cross compiled packages
          //
          (lib.listToAttrs (map (crossSystem: lib.nameValuePair
            "mlvpn-${crossSystem}"
            (buildFor (pkgsCross system crossSystem))
          ) otherSystems ))
          
          # cross compiled static packages
          //
          (lib.listToAttrs (map (crossSystem: lib.nameValuePair
            "mlvpn-static-${crossSystem}"
            (buildFor (pkgsCross system crossSystem).pkgsStatic)
          ) otherSystems ))
        );
      };
}
