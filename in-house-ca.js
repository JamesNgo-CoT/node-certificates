cobst attrs = [
    {
      name: "commonName",
      value: "rootCA.org",
    },
    {
      name: "countryName",
      value: "SY",
    },
    {
      shortName: "ST",
      value: "SYRIA",
    },
    {
      name: "localityName",
      value: "DAMAS",
    },
    {
      name: "organizationName",
      value: "DAMASCUS UNIVERSITY",
    },
    {
      shortName: "OU",
      value: "Testy",
    },
  ]

// Creating built-in CA store
(() => {

  // Libs
  const fs = require("fs");
  const rsaHandler = require("./rsa-handler");


  const Keys = rsaHandler.generatePublicPrivatePairOfKeys();
  const RootCAPrivateKey = Keys.privateKey;
  const RootCAPublicKey = Keys.publicKey;

  // Writing to files
  fs.writeFileSync("keys/root-ca/private-key.pem", RootCAPrivateKey, {
    encoding: "utf-8",
  });
  fs.writeFileSync("keys/root-ca/public-key.pem", RootCAPublicKey, {
    encoding: "utf-8",
  });

  // Generate CA certificate
  const certificatesGenerator = require("./certificate-generator");

  const CA = certificatesGenerator.generateCertificate(
    RootCAPrivateKey,
    RootCAPublicKey,
    attrs
  );

  // Writing to file
  fs.writeFileSync("ssl/ca/is-ca.pem", CA, {
    encoding: "utf-8",
  });
})();
