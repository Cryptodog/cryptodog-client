Cryptodog.keys = function () {
    'use strict';

    // a static salt is very much not ideal, but still better than the previous status quo of plaintext room names
    const baseKeySalt = '22ee85c3b14f73305d75d9c66f7687ef';
    const roomIdLength = 16;
    const roomKeyLength = 32;
    const roomIdCtx = 'room id';
    const roomKeyCtx = 'room key';
    const peerKeyCtx = 'peer key';

    function newPrivateKey() {
        return nacl.randomBytes(nacl.scalarMult.scalarLength);
    }

    function publicKeyFromPrivate(privateKey) {
        return nacl.scalarMult.base(privateKey);
    }

    function derivePeerKey(myPrivateKey, theirPublicKey, roomKey) {
        if (roomKey.length !== roomKeyLength) {
            throw new Error('invalid room key length');
        }
        const keyMaterial = Cryptodog.sodium.crypto_generichash(
            Cryptodog.sodium.crypto_kdf_KEYBYTES,
            new Uint8Array([
                ...nacl.scalarMult(myPrivateKey, theirPublicKey),
                ...roomKey
            ])
        );
        return Cryptodog.sodium.crypto_kdf_derive_from_key(nacl.secretbox.keyLength, 1, peerKeyCtx, keyMaterial);
    }

    async function deriveFromRoomName(roomName) {
        // derive base key from room name
        const baseKey = (await argon2.hash({
            pass: roomName,
            salt: baseKeySalt,
            type: argon2.ArgonType.Argon2id,
            hashLen: Cryptodog.sodium.crypto_kdf_KEYBYTES,
        })).hash;

        // derive room id (public value sent to server) from base key
        const roomId = arrayBufferToHex(
            Cryptodog.sodium.crypto_kdf_derive_from_key(roomIdLength, 1, roomIdCtx, baseKey)
        );
        // derive room secret from base key
        const roomKey = Cryptodog.sodium.crypto_kdf_derive_from_key(roomKeyLength, 2, roomKeyCtx, baseKey);

        return {
            roomId,
            roomKey
        };
    };

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
        derivePeerKey,
        deriveFromRoomName
    };
}();
