Cryptodog.keys = function () {
    'use strict';

    // a static salt is very much not ideal, but still better than the previous status quo of plaintext room names
    const baseKeySalt = '22ee85c3b14f73305d75d9c66f7687ef';
    const roomIdLength = 16;
    const roomKeyLength = 32;
    const roomIdCtx = 'room id';
    const roomKeyCtx = 'room key';
    const peerKeyCtx = 'peer key';

    function newKeyPair() {
        return Cryptodog.sodium.crypto_kx_keypair();
    };

    function derivePeerKey(myPrivateKey, theirPublicKey, roomKey) {
        if (roomKey.length !== roomKeyLength) {
            throw new Error('invalid room key length');
        }
        const keyMaterial = Cryptodog.sodium.crypto_generichash(
            Cryptodog.sodium.crypto_kdf_KEYBYTES,
            new Uint8Array([
                ...Cryptodog.sodium.crypto_scalarmult(myPrivateKey, theirPublicKey),
                ...roomKey
            ])
        );
        return Cryptodog.sodium.crypto_kdf_derive_from_key(Cryptodog.sodium.crypto_secretbox_KEYBYTES, 1, padContext(peerKeyCtx), keyMaterial);
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
        const roomId = Cryptodog.sodium.to_hex(
            Cryptodog.sodium.crypto_kdf_derive_from_key(roomIdLength, 1, padContext(roomIdCtx), baseKey)
        );
        // derive room secret from base key
        const roomKey = Cryptodog.sodium.crypto_kdf_derive_from_key(roomKeyLength, 2, padContext(roomKeyCtx), baseKey);

        return {
            roomId,
            roomKey
        };
    };

    // context should be an 8-character string: https://libsodium.gitbook.io/doc/key_derivation
    function padContext(ctx) {
        if (typeof ctx !== 'string') {
            throw new Error('invalid context type');
        }
        if (ctx.length > Cryptodog.sodium.crypto_kdf_CONTEXTBYTES) {
            throw new Error('context too long');
        }
        return ctx.padEnd(Cryptodog.sodium.crypto_kdf_CONTEXTBYTES, '_');
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
        newKeyPair,
        derivePeerKey,
        deriveFromRoomName
    };
}();
