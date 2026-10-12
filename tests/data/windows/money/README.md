# Microsoft Money fixtures (no script)

`tests/fixtures/external/ms-money/fillyfoal-{nopasswd,passwd}.mny.raw.zst` were made by hand in
Microsoft Money Plus Sunset Deluxe, `msmoney.exe` 17.00.3817 (32-bit x86, run under emulation on
Windows 11 Pro 25H2 ARM64, build 10.0.26200.9457, local account `fillyfoal`, time zone UTC). The
installer was `USMoneyDlxSunset.exe`, Authenticode-signed by Microsoft. A UI-automation attempt was
abandoned, so the steps are:

1. File > New, saved as `fillyfoal-nopasswd.mny`. Setup wizard: name `fillyfoal`, country US, all
   online services and sign-in offers declined.
2. Accounts & Bills > Add an account: bank `fillyfoal bank`, type Checking, name
   `fillyfoal checking`, opening balance 1000.00. Three transactions (-12.34, -56.78, 78.90).
3. File > Exit, backup prompt skipped.
4. With Money closed, copy the file to `fillyfoal-passwd.mny`, open it, set the file password
   `fillyfoal` (File > Password protection), File > Exit.

SHA-256 of the files as written (before `zstd -19`):

- `fillyfoal-nopasswd.mny` (3407872 bytes): `7eeb46151a5300e65612b14711a73512500d6eb75fed9228584ae5dca02a01a8`
- `fillyfoal-passwd.mny` (3510272 bytes): `61d2317f357bf8062f8cf5634a2812f5ea7ec912b88cb7746a5ce8abd62f0e4e`
