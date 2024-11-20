Cryptodog.keys = function () {
    // a static salt is very much not ideal, but still better than the previous status quo of plaintext room names
    const baseKeySalt = '22ee85c3b14f73305d75d9c66f7687ef';
    const hkdfSalt = new Uint8Array(16);
    const roomIdInfo = 'cryptodog room id';
    const roomSecretInfo = 'cryptodog room secret';

    function newPrivateKey() {
        const privateKeyLen = 32;
        return crypto.getRandomValues(new Uint8Array(privateKeyLen));
    }

    function publicKeyFromPrivate(privateKey) {
        return nacl.scalarMult.base(privateKey);
    }

    async function getPairwiseKey(myPrivateKey, theirPublicKey, myId, theirId, roomSecret) {
        const pairwiseKeyBits = 8 * nacl.secretbox.keyLength;

        const hkdfInput = new Uint8Array([...nacl.scalarMult(myPrivateKey, theirPublicKey), ...roomSecret]);
        const hdfkInputImported = await importForHkdf(hkdfInput);

        const sortedIds = [myId, theirId].sort().join();
        return new Uint8Array(
            await hkdf(hdfkInputImported,
                hkdfSalt,
                `pairwise key for ${sortedIds}`,
                pairwiseKeyBits
            )
        );
    }

    async function deriveFromRoomName(roomName) {
        // derive base key from room name
        const baseKey = await argon2.hash({
            pass: roomName,
            salt: baseKeySalt,
            type: argon2.ArgonType.Argon2id,
        });
        const baseKeyImported = await importForHkdf(baseKey.hash);

        // derive room id (public value sent to server) from base key
        const roomId = arrayBufferToHex(
            await hkdf(baseKeyImported, hkdfSalt, roomIdInfo, 128)
        );

        // derive room secret from base key
        const roomSecret = await hkdf(baseKeyImported, hkdfSalt, roomSecretInfo, 256);

        return {
            roomId,
            roomSecret: new Uint8Array(roomSecret)
        };
    };

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

    function importForHkdf(key) {
        return crypto.subtle.importKey(
            'raw',
            key,
            'HKDF',
            false,
            ['deriveBits']
        );
    }

    function arrayBufferToHex(buf) {
        return [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, '0')).join('');
    }

    Uint8Array.prototype.arrayEquals = function (otherArray) {
        if (this.length !== otherArray.length) {
            return false;
        }
        for (let i = 0; i < this.length; i++) {
            if (this[i] != otherArray[i]) {
                return false;
            }
        }
        return true;
    };

    return {
        newPrivateKey,
        publicKeyFromPrivate,
        getPairwiseKey,
        deriveFromRoomName
    };
}();
