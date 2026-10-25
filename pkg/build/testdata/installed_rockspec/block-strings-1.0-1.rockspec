package = "block-strings"
version = "1.0-1"
if not ok then
  local function f() if a then return end end
  for _, v in ipairs(t) do print(v) end
end
-- version == scm or not
description = {
  summary = "if this == that",
  stable = rock_version ~= "scm",
  detailed = [[
    fast and small, or not
  ]],
  license = 'MIT' -- and more
}
