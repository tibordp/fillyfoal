# Writes the R fixtures in tests/fixtures/external/r-serialized/ with
# R 4.4.1 (docker image r-base:4.4.1):
#
#   cd /tmp/fixtures/r-serialized
#   docker run --rm -v /tmp/fixtures/r-serialized:/work -w /work r-base:4.4.1 Rscript make_r.R
#
# All uncompressed XDR serializations (gzip-compressed ones are gzip
# files at the top level); reproducible byte for byte.
a <- c(1.5, 2.5, NA)
b <- list(name = "fillyfoal", n = 3L, ok = TRUE)
f <- factor(c("lo", "hi", "lo"))
df <- data.frame(x = 1:3, y = c("p", "q", "r"))

# Workspace (RDX3, serialization version 3).
save(a, b, f, df, file = "workspace.RData", compress = FALSE)
# Single objects: version 3 holding an ALTREP compact sequence, and
# version 2.
saveRDS(1:10, "altrep-v3.rds", compress = FALSE)
saveRDS(df, "df-v2.rds", compress = FALSE, version = 2)

# The other two serialization formats: ASCII (saveRDS/save with
# ascii = TRUE; strings escaped, doubles as text) and native binary
# (serialize(xdr = FALSE), little-endian on this platform).
x <- list(s = c("tab\there", "quote\"", NA, "žaba"), d = c(-1.25, NA, Inf, NaN),
          l = c(TRUE, FALSE, NA), z = complex(real = 1, imaginary = -2), r = as.raw(c(1, 255)))
saveRDS(x, "ascii.rds", ascii = TRUE, compress = FALSE)
save(a, b, file = "ascii.RData", ascii = TRUE, compress = FALSE)
writeBin(serialize(x, NULL, xdr = FALSE), "native.rds")

# Closures, an environment and byte code.
e <- new.env()
assign("k", 42L, envir = e)
g <- function(x, y = 2) x + y
saveRDS(list(fn = g, env = e, bc = compiler::cmpfun(function(v) v * 2)), "closure.rds",
        compress = FALSE)
