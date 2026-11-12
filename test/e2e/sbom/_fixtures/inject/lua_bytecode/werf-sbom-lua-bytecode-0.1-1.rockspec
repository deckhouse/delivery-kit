package = "werf-sbom-lua-bytecode"
version = "0.1-1"
source = {
   url = "git+https://github.com/example/werf-sbom-lua-bytecode.git"
}
description = {
   summary = "werf e2e SBOM compiled Lua siblings fixture",
   homepage = "https://github.com/example/werf-sbom-lua-bytecode",
   license = "MIT"
}
dependencies = {
   "lua >= 5.1",
   "inspect == 3.1.3-0",
   "ansicolors == 1.0.2-3"
}
build = {
   type = "builtin",
   modules = {
      app = "app.lua"
   }
}
