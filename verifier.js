module.exports = {
  verifyCertificate: (certPem) => {
    const log = console.log;
    let pki = require("node-forge").pki;
    let fs = require("fs");

    let caCert;
    let caStore;

    try {
      caCert = fs.readFileSync("ssl/ca/is-ca.pem", {
        encoding: "utf-8",
      });

      caStore = pki.createCaStore([caCert]);
    } catch (e) {
      log("Failed to load CA certificate (" + e + ")");
      return false;
    }

    try {
      const certToVerify = pki.certificateFromPem(certPem);
      const verified = pki.verifyCertificateChain(caStore, [certToVerify]);
      if (verified) {
        log("Certificate got verified successfully.!");
      }
      return verified;
    } catch (e) {
      log("Failed to verify certificate (" + (e.message || e) + ")");
      return false;
    }
  },
};
