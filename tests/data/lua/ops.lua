-- Opcode sampler for tests/fixtures/external/lua/ops-5.*.luac: one
-- source that every Lua from 5.1 to 5.5 compiles, using as many kinds of
-- instruction as plain syntax reaches (arithmetic, comparisons, tests,
-- tables, loops, closures, varargs, method calls, multiple returns).
local t = { 1, 2, 3, x = 4, ["y z"] = 5, nested = { true, false, nil } }
local s, n = "str", 0
local a, b = 7, 2.5

local function arith(x, y)
  return x + y, x - y, x * y, x / y, x % y, x ^ y, -x, #s, s .. x
end

local function compare(x, y)
  if x == y then n = n + 1 end
  if x ~= y then n = n + 2 end
  if x < y then n = n + 3 end
  if x <= y then n = n + 4 end
  if x > 1 and y >= 2 or not x then n = n + 5 end
  local c = x and y or false
  return c
end

local obj = { v = 1 }
function obj:get(k) return self.v + k end
function obj.set(self, v) self.v = v end

local function loops(...)
  local sum = 0
  for i = 1, 10, 2 do sum = sum + i end
  for k, v in pairs(t) do if type(v) == "number" then sum = sum + v end end
  local i = 0
  while i < 3 do i = i + 1 end
  repeat i = i - 1 until i <= 0
  local args = { ... }
  local first = ...
  return sum, #args, first, select("#", ...)
end

local function counter()
  local count = 0
  return function(step)
    count = count + (step or 1)
    return count
  end
end

local c = counter()
c(); c(5)
t[1], t.x = t.x, t[1]
t[a] = b
obj:set(42)
print(arith(a, b))
print(compare(a, b), obj:get(1), loops(1, 2, 3))
return t, obj
