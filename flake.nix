{
  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
  };

  outputs = inp:
    let
      pkgs = inp.nixpkgs.legacyPackages.x86_64-linux;
    in
    {
      defaultPackage.x86_64-linux = pkgs.stdenv.mkDerivation {
        src = ./.;
        name = "mlvpn";
        buildInputs = with pkgs; [
          automake
          autoconf
          libev
          libsodium
          libpcap
          pkg-config
        ];
        preConfigure = ''
          ./autogen.sh
        '';
      };
    };
}
