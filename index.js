const fs = require('fs');

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
		{ shortName: 'CN', value: 'WSS-NonPROD-PAYMENT-2022-02-03' },
		{ shortName: 'OU', value: 'WSS-NonPROD-PAYMENT' },
		{ shortName: 'O', value: 'City of Toronto' },
		{ shortName: 'L', value: 'Toronto' },
		{ shortName: 'ST', value: 'Ontario' },
		{ shortName: 'C', value: 'CA' }
	]);
	csr.sign(prKey);

	return forge.pki.certificationRequestToPem(csr);
}

const { privateKey, publicKey } = generateKeyPair();

console.log('PRIVATE KEY', privateKey);
fs.writeFileSync('private.ppk', privateKey, 'utf-8');

console.log('PUBLIC KEY', publicKey);
fs.writeFileSync('public.pub', publicKey, 'utf-8');

const csr = generateCsr(privateKey, publicKey);
console.log('CSR', csr);
fs.writeFileSync('csr.pem', publicKey, 'utf-8');
