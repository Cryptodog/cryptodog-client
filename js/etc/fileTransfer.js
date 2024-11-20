$(window).ready(function() {
    'use strict';

    window.sodium = {
        onload: function (sodium) {
            Cryptodog.sodium = sodium;
        }
    };

    // Maximum encrypted file sharing size, in kilobytes.
    Cryptodog.otr.maximumFileSize = 5120;

    // Size in which file chunks are split, in bytes.
    Cryptodog.otr.chunkSize = 64511;

    // Safari compatibility
    window.URL = window.URL || window.webkitURL;

    var files = {};
    var rcvFile = {};
    var fileMIME = new RegExp(
        '^(image/(png|jpeg|gif))|(application/((x-compressed)|(x-zip-compressed)|(zip)' +
            '|(x-zip)|(octet-stream)|(x-compress)))|(multipart/x-zip)$'
    );

    var cn = function(to) {
        return Cryptodog.me.conversation + '@' + Cryptodog.xmpp.currentServer.conference + '/' + to;
    };

    Cryptodog.otr.beginSendFile = function(data) {
        if (!data.file.type.match(fileMIME)) {
            $('#fileInfoField').text(Cryptodog.locale['chatWindow']['fileTypeError']);
            return;
        } else if (data.file.size > Cryptodog.otr.maximumFileSize * 1024) {
            $('#fileInfoField').text(
                Cryptodog.locale['chatWindow']['fileSizeError'].replace('(SIZE)', Cryptodog.otr.maximumFileSize / 1024)
            );
            return;
        } else {
            window.setTimeout(function() {
                $('#dialogBoxClose').click();
            }, 500);
        }

        var sid = Cryptodog.xmpp.connection.getUniqueId();
        files[sid] = {
            to: data.to,
            position: 0,
            file: data.file,
            total: Math.ceil(data.file.size / Cryptodog.otr.chunkSize),
            ctr: -1
        };

        Cryptodog.xmpp.connection.si_filetransfer.send(
            cn(data.to),
            sid,
            data.filename,
            data.file.size,
            data.file.type,

            function(err) {
                if (err) {
                    return console.log(err);
                }

                Cryptodog.xmpp.connection.ibb.open(cn(data.to), sid, Cryptodog.otr.chunkSize, function (err) {
                    if (err) {
                        return console.log(err);
                    }
                    Cryptodog.addToConversation(sid, Cryptodog.me.nickname, Cryptodog.buddies[data.to].id, 'file');

                    // Initialize sender secretstream
                    const stream = Cryptodog.sodium.crypto_secretstream_xchacha20poly1305_init_push(
                        // TODO: should we use a unique per-transfer key?
                        Cryptodog.buddies[data.to].mpSecretKey
                    );

                    // Send header
                    Cryptodog.xmpp.connection.ibb.data(cn(data.to), sid, 0, Cryptodog.sodium.to_base64(stream.header), function (err) {
                        if (err) {
                            return console.log(err);
                        }
                        Cryptodog.otr.sendFileData({
                            seq: 1,
                            to: data.to,
                            sid: sid,
                            state: stream.state
                        });
                    });
                });
            }
        );
    };

    Cryptodog.otr.sendFileData = function(data) {
        var sid = data.sid;
        var seq = data.seq;
        if (seq > 65535) {
            seq = 0;
        }

        // Split into chunk
        var end = files[sid].position + Cryptodog.otr.chunkSize;

        // Check for slice function on file
        var sliceStr = files[sid].file.slice ? 'slice' : 'webkitSlice';
        var chunk = files[sid].file[sliceStr](files[sid].position, end);

        files[sid].position = end;
        files[sid].ctr += 1;

        var reader = new FileReader();
        reader.onload = function(event) {
            const chunkBytes = new Uint8Array(event.target.result);

            let streamTag, cb;
            if (files[sid].position > files[sid].file.size) {
                // The final chunk
                streamTag = Cryptodog.sodium.crypto_secretstream_xchacha20poly1305_TAG_FINAL;
                cb = (data, sid, files) => {
                    Cryptodog.xmpp.connection.ibb.close(cn(data.to), sid, function (err) {
                        if (err) {
                            return console.log(err);
                        }
                    });
                    Cryptodog.updateFileProgressBar(sid, files[sid].ctr + 1, files[sid].file.size, data.to);
                };
            } else {
                // An intermediate chunk
                streamTag = Cryptodog.sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE;
                cb = (data, sid) => {
                    Cryptodog.otr.sendFileData({
                        seq: seq + 1,
                        to: data.to,
                        sid: sid,
                        state: data.state
                    });
                };
            }
            const encryptedChunk = Cryptodog.sodium.crypto_secretstream_xchacha20poly1305_push(
                data.state,
                chunkBytes,
                null,
                streamTag,
            );
            Cryptodog.xmpp.connection.ibb.data(cn(data.to), sid, seq,
                Cryptodog.sodium.to_base64(encryptedChunk), function(err) {
                if (err) {
                    return console.log(err);
                }
                cb(data, sid, files);
            });

            Cryptodog.updateFileProgressBar(sid, files[sid].ctr + 1, files[sid].file.size, data.to);
        };
        reader.readAsArrayBuffer(chunk);
    };

    Cryptodog.otr.ibbHandler = function(type, from, sid, data, seq) {
        var nick = from.split('/')[1];

        switch (type) {
            case 'open':
                // Latest version of Strophe.js (2017-09-30) uses this UID format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
                // https://github.com/strophe/strophejs/blob/ea459e987cc166b33a33efa99cac9b02beb12a98/strophe.js#L2916
                // But doing this match at all seems unnecessary.
                // TODO: Look into ramifications of removing it.
                if (sid.match(/^\w{8}-\w{4}-4\w{3}-\w{4}-\w{12}$/) && rcvFile[from][sid].mime.match(fileMIME)) {
                    Cryptodog.addToConversation(sid, nick, Cryptodog.buddies[nick].id, 'file');
                }
                break;
            case 'data':
                if (rcvFile[from][sid].abort) {
                    return;
                }

                if (rcvFile[from][sid].ctr > rcvFile[from][sid].total - 1) {
                    rcvFile[from][sid].abort = true;
                    Cryptodog.UI.fileTransferError(sid, nick);
                    return;
                }

                rcvFile[from][sid].seq = seq;

                if (!rcvFile[from][sid].state) {
                    // No secretstream established yet; this message should be the header
                    const header = Cryptodog.sodium.from_base64(data);
                    const state = Cryptodog.sodium.crypto_secretstream_xchacha20poly1305_init_pull(
                        header, Cryptodog.buddies[nick].mpSecretKey
                    );
                    if (!state) {
                        rcvFile[from][sid].abort = true;
                        Cryptodog.UI.fileTransferError(sid, nick);
                        return;
                    }
                    rcvFile[from][sid].state = state;
                    return;
                }

                // We have a secretstream; try to decrypt this chunk
                const r = Cryptodog.sodium.crypto_secretstream_xchacha20poly1305_pull(rcvFile[from][sid].state,
                    Cryptodog.sodium.from_base64(data));
                if (!r) {
                    // TODO: decide how to present these errors to the user
                    throw new Error(`failed to decrypt file chunk from ${nick}`);
                }

                rcvFile[from][sid].data = [...rcvFile[from][sid].data, ...r.message];
                rcvFile[from][sid].ctr += 1;
                Cryptodog.updateFileProgressBar(sid, rcvFile[from][sid].ctr, rcvFile[from][sid].size, nick);
                break;
            case 'close':
                if (!rcvFile[from][sid].abort && rcvFile[from][sid].total === rcvFile[from][sid].ctr) {
                    var blob = new Blob([new Uint8Array(rcvFile[from][sid].data)], { type: rcvFile[from][sid].mime });
                    const url = window.URL.createObjectURL(blob);

                    if (rcvFile[from][sid].filename.match(/^[\w.\-]+$/) && rcvFile[from][sid].mime.match(fileMIME)) {
                        Cryptodog.addFile(url, sid, nick, rcvFile[from][sid].filename);
                    } else {
                        Cryptodog.UI.fileTransferError(sid, nick);

                        console.log(
                            'Received file of unallowed file type ' + rcvFile[from][sid].mime + ' from ' + nick
                        );
                    }
                }
                delete rcvFile[from][sid];
                break;
        }
    };

    Cryptodog.otr.fileHandler = function(from, sid, filename, size, mime) {
        if (!rcvFile[from]) {
            rcvFile[from] = {};
        }

        rcvFile[from][sid] = {
            filename: filename,
            size: size,
            mime: mime,
            seq: 0,
            ctr: 0,
            total: Math.ceil(size / Cryptodog.otr.chunkSize),
            abort: false,
            data: new Uint8Array(),
            state: null
        };
    };
});
