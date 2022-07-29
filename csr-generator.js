module.exports = {
  generateCSR: (privateKey, publicKey) => {

    const forge = require("node-forge");
    const pki = forge.pki;


    const prKey = pki.privateKeyFromPem(privateKey);
    const pubKey = pki.publicKeyFromPem(publicKey);

    // generate a key pair
    // const keys = forge.pki.rsa.generateKeyPair(1024);

    // create a certification request (CSR)
    const csr = forge.pki.createCertificationRequest();
    csr.publicKey = pubKey;
    csr.setSubject([
      {
        name: "commonName",
        value: "example.org",
      },
      {
        name: "countryName",
        value: "US",
      },
      {
        shortName: "ST",
        value: "Virginia",
      },
      {
        name: "localityName",
        value: "Blacksburg",
      },
      {
        name: "organizationName",
        value: "Test",
      },
      {
        shortName: "OU",
        value: "Test",
      },
    ]);
    // set (optional) attributes
    csr.setAttributes([
      {
        name: "challengePassword",
        value: "password",
      },
      {
        name: "unstructuredName",
        value: "My Company, Inc.",
      },
      {
        name: "extensionRequest",
        extensions: [
          {
            name: "subjectAltName",
            altNames: [
              {
                // 2 is DNS type
                type: 2,
                value: "localhost",
              },
              {
                type: 2,
                value: "127.0.0.1",
              },
              {
                type: 2,
                value: "www.domain.net",
              },
            ],
          },
        ],
      },
    ]);

    // sign certification request
    csr.sign(prKey);

    // verify certification request
    const verified = csr.verify();

    // convert certification request to PEM-format
    const pem = forge.pki.certificationRequestToPem(csr);

    // convert a Forge certification request from PEM-format
    // const csr = forge.pki.certificationRequestFromPem(pem);

    // get an attribute
    // csr.getAttribute({ name: "challengePassword" });

    // get extensions array
    // csr.getAttribute({ name: "extensionRequest" }).extensions;
    
    return pem;
  },
};
