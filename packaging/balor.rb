class Balor < Formula
  desc "Rust-native L4/L7 load balancer with Axum admin API + Yew UI"
  homepage "https://github.com/arencloud/balor"
  url "https://github.com/arencloud/balor/archive/refs/tags/v0.1.2.tar.gz"
  sha256 "<REPLACE_ME_WITH_REAL_SHA256>"
  license "Apache-2.0"

  depends_on "rust" => :build
  depends_on "wasm-pack"
  depends_on "trunk"

  def install
    system "rustup", "target", "add", "wasm32-unknown-unknown"
    system "cargo", "install", "trunk"
    system "cd", "admin", "&&", "trunk", "build", "--release"
    system "cargo", "install", "--locked", *std_cargo_args(path: "backend")
    pkgshare.install "admin/dist"
  end

  def caveats
    <<~EOS
      BALOR_ADMIN_DIST defaults to #{opt_pkgshare}/dist after install:
        export BALOR_ADMIN_DIST=#{opt_pkgshare}/dist
      Run the server with:
        balor
    EOS
  end
end
