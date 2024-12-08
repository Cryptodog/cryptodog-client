Cryptodog.multiParty = function () { };

(function () {
    'use strict';

    Cryptodog.multiParty.maxMessageLength = 5000;

    const usedNonces = new Set();
    function markNonceUsed(nonce) {
        usedNonces.add(Cryptodog.sodium.to_base64(nonce));
    }
    function nonceIsUsed(nonce) {
        return usedNonces.has(Cryptodog.sodium.to_base64(nonce));
    }

    Cryptodog.multiParty.PublicKey = function (key) {
        this.type = 'public_key';
        this.text = Cryptodog.sodium.to_base64(key);
    };

    Cryptodog.multiParty.PublicKeyRequest = function (name) {
        this.type = 'public_key_request';
        if (name) {
            this.text = name;
        } else {
            this.text = '';
        }
    };

    Cryptodog.multiParty.encryptDirectMessage = function (recipient, message) {
        const nonce = Cryptodog.sodium.randombytes_buf(Cryptodog.sodium.crypto_secretbox_NONCEBYTES);
        markNonceUsed(nonce);
        const ct = Cryptodog.sodium.crypto_secretbox_easy(
            Cryptodog.sodium.from_string(message),
            nonce,
            Cryptodog.buddies[recipient].peerKey
        );

        return JSON.stringify({
            nonce: Cryptodog.sodium.to_base64(nonce),
            ct: Cryptodog.sodium.to_base64(ct)
        });
    };

    Cryptodog.multiParty.decryptDirectMessage = function (sender, message) {
        let { ct, nonce } = JSON.parse(message);
        ct = Cryptodog.sodium.from_base64(ct);
        nonce = Cryptodog.sodium.from_base64(nonce);

        if (nonceIsUsed(nonce)) {
            throw new Error('nonce reuse');
        }
        markNonceUsed(nonce);

        const plaintext = Cryptodog.sodium.crypto_secretbox_open_easy(
            ct,
            nonce,
            Cryptodog.buddies[sender].peerKey
        );

        return Cryptodog.sodium.to_string(plaintext);
    };

    Cryptodog.multiParty.sendMessage = function (message) {
        message = Cryptodog.sodium.from_string(message);

        var encrypted = {
            text: {},
            type: 'message'
        };

        var sortedRecipients = [];
        for (var b in Cryptodog.buddies) {
            if (Cryptodog.buddies[b].peerKey) {
                sortedRecipients.push(b);
            }
        }
        sortedRecipients.sort();

        for (var i = 0; i < sortedRecipients.length; i++) {
            const nonce = Cryptodog.sodium.randombytes_buf(Cryptodog.sodium.crypto_secretbox_NONCEBYTES);
            markNonceUsed(nonce);
            encrypted['text'][sortedRecipients[i]] = {};
            encrypted['text'][sortedRecipients[i]]['message'] = Cryptodog.sodium.to_base64(
                Cryptodog.sodium.crypto_secretbox_easy(
                    message,
                    nonce,
                    Cryptodog.buddies[sortedRecipients[i]].peerKey
                )
            );
            encrypted['text'][sortedRecipients[i]]['nonce'] = Cryptodog.sodium.to_base64(nonce);
        }
        return JSON.stringify(encrypted);
    };

    Cryptodog.multiParty.receiveMessage = async function (sender, myName, message) {
        var buddy = Cryptodog.buddies[sender];

        try {
            message = JSON.parse(message);
        } catch (err) {
            console.log('multiParty: failed to parse message object');
            return false;
        }

        var type = message.type;

        if (type === 'public_key') {
            if (typeof message.text !== 'string') {
                console.log('multiParty: invalid public key from ' + sender);
                return false;
            }

            var publicKey = Cryptodog.sodium.from_base64(message.text);

            // TODO: verify these checks work as expected
            if (buddy.publicKey && buddy.publicKey.arrayEquals(publicKey)) {
                // We already have this key.
                return false;
            } else if (buddy.publicKey && !buddy.publicKey.arrayEquals(publicKey)) {
                // If it's a different key than the one we have, warn user.
                Cryptodog.UI.removeAuthAndWarn(sender);
            } else if (!buddy.publicKey && buddy.authenticated) {
                // If we're missing their key and they're authenticated, warn user (prevents a possible active attack).
                Cryptodog.UI.removeAuthAndWarn(sender);
            }

            // TODO: check whether this needs to be put back into a worker
            buddy.peerKey = Cryptodog.keys.derivePeerKey(Cryptodog.me.keyPair.privateKey, publicKey, Cryptodog.me.roomKey);
            buddy.publicKey = publicKey;

            // TODO: set fingerprint/safety number for buddy
        } else if (type === 'public_key_request') {
            if (!message.text || message.text === Cryptodog.me.nickname) {
                Cryptodog.xmpp.sendPublicKey();
            }
        } else if (type === 'message') {
            var text = message['text'];

            if (!text || typeof text !== 'object') {
                return false;
            }

            if (!text[myName] || typeof text[myName] !== 'object') {
                console.log('multiParty: invalid message from ' + sender);
                Cryptodog.UI.messageWarning(sender, false);
                return false;
            } else {
                if (!(buddy.peerKey)) {
                    // We don't have the sender's key - they're "borked".
                    // Request their key and warn the user.
                    console.log('Requesting public key from ' + sender);
                    Cryptodog.xmpp.requestPublicKey(sender);
                    Cryptodog.UI.messageWarning(sender, false);
                    return false;
                }

                var recipients = Object.keys(Cryptodog.buddies);
                recipients.push(Cryptodog.me.nickname);
                recipients.splice(recipients.indexOf(sender), 1);

                // Find missing recipients: those for whom the message isn't encrypted
                var missingRecipients = [];

                for (var i = 0; i < recipients.length; i++) {
                    try {
                        if (typeof text[recipients[i]] === 'object') {
                            var noMessage = typeof text[recipients[i]]['message'] !== 'string';
                            var noNonce = typeof text[recipients[i]]['nonce'] !== 'string';

                            if (noMessage || noNonce) {
                                missingRecipients.push(recipients[i]);
                            }
                        } else {
                            missingRecipients.push(recipients[i]);
                        }
                    } catch (err) {
                        missingRecipients.push(recipients[i]);
                    }
                }
                if (text[myName]['message'].length > Cryptodog.multiParty.maxMessageLength) {
                    Cryptodog.UI.messageWarning(sender, false);
                    console.log('multiParty: refusing to decrypt large message (' + text[myName]['message'].length + ' bytes) from ' + sender);
                    return false;
                }

                const ct = Cryptodog.sodium.from_base64(text[myName]['message']);
                const nonce = Cryptodog.sodium.from_base64(text[myName]['nonce']);
                if (nonceIsUsed(nonce)) {
                    throw new Error('nonce reuse');
                }
                markNonceUsed(nonce);

                // TODO: verify 1) that no recipient's ciphertext was tampered with and 2) that everyone received the same plaintext
                const plaintext = Cryptodog.sodium.crypto_secretbox_open_easy(ct, nonce, buddy.peerKey);

                // Only show "missing recipients" warning if the message is readable
                if (missingRecipients.length) {
                    Cryptodog.addToConversation(missingRecipients, sender, 'groupChat', 'missingRecipients');
                }
                return Cryptodog.sodium.to_string(plaintext);
            }
        } else {
            console.log('multiParty: unknown message type "' + type + '" from ' + sender);
        }

        return false;
    };

    // Reset everything except my own key pair
    Cryptodog.multiParty.reset = function () {
    };
})();
