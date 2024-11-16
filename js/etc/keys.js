Cryptodog.keys = function () { };

(function () {
    // a static salt is very much not ideal, but still better than the previous status quo of plaintext room names
    const baseKeySalt = '22ee85c3b14f73305d75d9c66f7687ef';
    const hkdfSalt = new Uint8Array(16);
    const roomIdInfo = 'cryptodog room id';
    const roomSecretInfo = 'cryptodog room secret';

    function hkdf(keyImported, salt, info, numBits) {
        if (numBits < 128) {
            throw new Error(`numBits too small for hkdf (${numBits} < 128)`);
        }
        return crypto.subtle.deriveBits(
            {
                name: 'HKDF',
                salt: salt,
                info: new TextEncoder().encode(info),
                hash: 'SHA-512'
            },
            keyImported,
            numBits,
        );
    }

    function arrayBufferToHex(buf) {
        return [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, '0')).join('');
    }

    Cryptodog.keys.deriveFromRoomName = async function (roomName) {
        // derive base key from room name
        const baseKey = await argon2.hash({
            pass: roomName,
            salt: baseKeySalt,
            type: argon2.ArgonType.Argon2id,
        });
        const baseKeyImported = await crypto.subtle.importKey(
            'raw',
            baseKey.hash,
            'HKDF',
            false,
            ['deriveBits']
        );

        // derive room id (public value sent to server) from base key
        const roomId = arrayBufferToHex(
            await hkdf(baseKeyImported, hkdfSalt, roomIdInfo, 128)
        );

        // derive room secret (currently unused) from base key
        const roomSecret = await hkdf(baseKeyImported, hkdfSalt, roomSecretInfo, 256);

        return {
            roomId,
            roomSecret,
        };
    };
}());
