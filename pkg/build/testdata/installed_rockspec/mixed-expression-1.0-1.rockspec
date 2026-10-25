package = "mixed-expression"
version = "1.0-1"
local base, suffix = "https://example.test/src", flag and "-dev" or ""

source = { url = base .. suffix }
description = { license = "MIT" }
