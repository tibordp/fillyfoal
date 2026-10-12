// Writes boarding.pkpass with passkit-generator (see make.sh): a generic
// pass with a QR barcode and a 2x2 icon, signed with the throwaway
// certificates make.sh creates.
const fs = require("fs");
const { PKPass } = require("passkit-generator");

const icon = Buffer.from(
  "89504e470d0a1a0a0000000d4948445200000002000000020802000000fdd49a73" +
    "000000104944415478da63d0a83801440c100a0024ee05a119868eaa00000000" +
    "49454e44ae426082",
  "hex",
);

const pass = new PKPass(
  {
    "pass.json": Buffer.from(
      JSON.stringify({
        formatVersion: 1,
        passTypeIdentifier: "pass.org.example.fillyfoal",
        teamIdentifier: "FILLYFOAL0",
        serialNumber: "0001",
        organizationName: "fillyfoal",
        description: "fillyfoal test pass",
        generic: {
          primaryFields: [{ key: "name", label: "NAME", value: "fillyfoal" }],
        },
        barcodes: [
          {
            format: "PKBarcodeFormatQR",
            message: "fillyfoal",
            messageEncoding: "iso-8859-1",
          },
        ],
      }),
    ),
    "icon.png": icon,
  },
  {
    wwdr: fs.readFileSync("wwdr.pem"),
    signerCert: fs.readFileSync("signer.pem"),
    signerKey: fs.readFileSync("signer.key"),
  },
);
fs.writeFileSync("boarding.pkpass", pass.getAsBuffer());
