package = "werf-sbom-lua-installed"
version = "0.1-1"
source = {
   url = "git+https://github.com/example/werf-sbom-lua-installed.git"
}
description = {
   summary = "werf e2e SBOM installed-packages lua fixture",
   homepage = "https://github.com/example/werf-sbom-lua-installed",
   license = "MIT"
}
dependencies = {
   "lua >= 5.1",
   "luassert == 1.9.0-1"
}
build = {
   type = "builtin",
   modules = {
      app = "app.lua"
   }
}
