importScripts('../lib/crypto-js.js', '../lib/bigint.mod.js', '../lib/elliptic.js');

onmessage = function (event) {
    let sharedSecret = genSharedSecret(event.data.theirPublicKey, event.data.ourPrivateKey, event.data.roomSecret);
    postMessage({ theirName: event.data.theirName, secretKey: sharedSecret });
};

// convert a Uint8Array to a WordArray
const toWordArray = function (uint8Arr) {
    var wa = [], i;
    for (i = 0; i < uint8Arr.length; i++) {
        wa[(i / 4) | 0] |= uint8Arr[i] << (24 - 8 * i);
    }
    return CryptoJS.lib.WordArray.create(wa, uint8Arr.length);
};

// Generate shared secrets
// First 256 bytes are for encryption, last 256 bytes are for HMAC.
// Represented as WordArrays
function genSharedSecret(theirPublicKey, ourPrivateKey, roomSecret) {
    // I need to convert the BigInt to WordArray here. I do it using the Base64 representation.
    var sharedSecret = CryptoJS.SHA512(
        CryptoJS.enc.Base64.parse(
            BigInt.bigInt2base64(
                Curve25519.ecDH(ourPrivateKey, theirPublicKey),
                32
            )
        )
    );
    // concat the room secret to the hashed DH output, and hash that to get the final shared secret
    const mixed = sharedSecret.concat(toWordArray(roomSecret));
    sharedSecret = CryptoJS.SHA512(mixed);

    return {
        message: sharedSecret.words.slice(0, 8),
        hmac: sharedSecret.words.slice(8, 16)
    };
};
