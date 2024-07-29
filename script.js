// Load jsencrypt library (make sure to include it in your project)
const crypt = new JSEncrypt();

// AES Encryption
function encryptAES() {
    const plaintext = document.getElementById('inputText').value;
    const encrypted = CryptoJS.AES.encrypt(plaintext, 'secretkey123').toString();
    document.getElementById('aesOutput').value = encrypted;
}

// AES Decryption
function decryptAES() {
    const ciphertext = document.getElementById('aesOutput').value;
    const decrypted = CryptoJS.AES.decrypt(ciphertext, 'secretkey123').toString(CryptoJS.enc.Utf8);
    document.getElementById('inputText').value = decrypted;
}

// RSA Encryption
function encryptRSA() {
    const plaintext = document.getElementById('rsaInput').value;
    crypt.setPublicKey(document.getElementById('publicKey').value); // Use generated RSA public key
    const encrypted = crypt.encrypt(plaintext);
    document.getElementById('rsaOutput').value = encrypted;
}

// RSA Decryption
function decryptRSA() {
    const ciphertext = document.getElementById('rsaOutput').value;
    crypt.setPrivateKey(document.getElementById('privateKey').value); // Use generated RSA private key
    const decrypted = crypt.decrypt(ciphertext);
    document.getElementById('rsaInput').value = decrypted;
}

// RSA Key Generation
function generateKeyPair() {
    const keyLength = parseInt(document.getElementById('keyLength').value);
    const crypt = new JSEncrypt({ default_key_size: keyLength });
    const publicKey = crypt.getPublicKey();
    const privateKey = crypt.getPrivateKey();
    document.getElementById('publicKey').value = publicKey;
    document.getElementById('privateKey').value = privateKey;
}

