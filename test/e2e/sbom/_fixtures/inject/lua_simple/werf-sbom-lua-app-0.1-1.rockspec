package = "werf-sbom-lua-app"
version = "0.1-1"
source = {
   url = "git+https://github.com/example/werf-sbom-lua-app.git"
}
description = {
   summary = "werf e2e SBOM lua-rock fixture",
   homepage = "https://github.com/example/werf-sbom-lua-app",
   license = "MIT"
}
dependencies = {
   "lua >= 5.1"
}
build = {
   type = "builtin",
   modules = {
      app = "app.lua"
   }
}
