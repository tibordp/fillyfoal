-- Sample for the luac fixtures in tests/fixtures/external/lua/: nested
-- functions and closures (upvalues), constants of every kind (nil,
-- booleans, integers, floats, short and long strings), varargs, locals
-- and a loop.
local greeting = "hello from fillyfoal"
local long = "a long string constant, longer than forty characters, so " ..
  "Lua 5.3 and later store it as a long string; and one over 255 bytes: " ..
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

local function counter(start)
  local n = start
  return function(step)
    n = n + (step or 1)
    return n
  end
end

local function stats(...)
  local total, count = 0, select("#", ...)
  for i = 1, count do
    total = total + select(i, ...)
  end
  return total / count, count > 0, nil
end

local c = counter(10)
c()
c(2.5)
print(greeting, #long, stats(1, 2, 3, 4.25), -7, 1e100, true, false)
