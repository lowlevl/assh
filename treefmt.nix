{...}: {
  # Used to find the project root
  projectRootFile = "flake.nix";

  programs = {
    alejandra.enable = true;
    rustfmt.enable = true;
    taplo = {
      enable = true;

      settings.formatting = {
        allowed_blank_lines = 1;
      };
    };
  };
}
