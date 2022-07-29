function generateKeyPair() {
	const crypto = require('crypto');
	return crypto.generateKeyPairSync('rsa', {
		modulusLength: 2048,
		publicKeyEncoding: {
			type: 'spki',
			format: 'pem'
		},
		privateKeyEncoding: {
			type: 'pkcs8',
			format: 'pem'
			// cipher: 'aes-256-cbc',
			// passphrase: 'top secret'
		}
	});
}

function generateCsr(privateKey, publicKey) {
	const forge = require('node-forge');
	const pki = forge.pki;

	const prKey = pki.privateKeyFromPem(privateKey);
	const pubKey = pki.publicKeyFromPem(publicKey);

	const csr = forge.pki.createCertificationRequest();
	csr.publicKey = pubKey;
	csr.setSubject([
		{ name: 'commonName', value: 'example.org' },
		{ name: 'countryName', value: 'US' },
		{ shortName: 'ST', value: 'Virginia' },
		{ name: 'localityName', value: 'Blacksburg' },
		{ name: 'organizationName', value: 'Test' },
		{ shortName: 'OU', value: 'Test' }
	]);
	csr.setAttributes([
		{ name: 'challengePassword', value: 'password' },
		{ name: 'unstructuredName', value: 'My Company, Inc.' },
		{
			name: 'extensionRequest',
			extensions: [
				{
					name: 'subjectAltName',
					altNames: [
						{ type: 2, value: 'localhost' },
						{ type: 2, value: '127.0.0.1' },
						{ type: 2, value: 'www.domain.net' }
					]
				}
			]
		}
	]);
	csr.sign(prKey);

	return forge.pki.certificationRequestToPem(csr);
}

const { privateKey, publicKey } = generateKeyPair();
console.log('PRIVATE KEY', privateKey);
console.log('PUBLIC KEY', publicKey);

const csr = generateCsr(privateKey, publicKey);
console.log('CSR', csr);
