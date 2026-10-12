-- Sample for tests/fixtures/external/lua/sample-5.0*.luac (Lua 5.0 has
-- no `#`, `%` or `...` expressions: varargs arrive in `arg`). Locals,
-- upvalues and closures, varargs, table constructors and fields, numeric
-- and generic for, while and repeat loops, string, number, boolean and
-- nil constants, comparisons, method calls and nested functions.
local greeting = "hello from fillyfoal"
local t = { 1, 2, 3, x = 4, ["y z"] = 5, nested = { true, false } }
local a, b = 7, 2.5

local function counter(start)
  local n = start
  return function(step)
    n = n + (step or 1)
    return n
  end
end

local function stats(...)
  local total, count = 0, arg.n
  for i = 1, count do
    total = total + arg[i]
  end
  return total / count, count > 0, nil
end

local function arith(x, y)
  return x + y, x - y, x * y, x / y, x ^ y, -x, greeting .. x
end

local function compare(x, y)
  local r = 0
  if x == y then r = r + 1 end
  if x ~= y then r = r + 2 end
  if x < y then r = r + 3 end
  if x <= y then r = r + 4 end
  if x > 1 and y >= 2 or not x then r = r + 5 end
  return x and y or false
end

local obj = { v = 1 }
function obj:get(k) return self.v + k end
function obj.set(self, v) self.v = v end

local function loops()
  local sum = 0
  for i = 10, 1, -2 do sum = sum + i end
  for k, v in pairs(t) do
    if type(v) == "number" then sum = sum + v end
  end
  local i = 0
  while i < 3 do i = i + 1 end
  repeat i = i - 1 until i <= 0
  return sum
end

local c = counter(10)
c()
c(2.5)
t[a] = b
obj:set(42)
print(greeting, stats(1, 2, 3, 4.25), -7, 1e100, true, false)
print(arith(a, b))
print(compare(a, b), obj:get(1), loops())
return t, obj
