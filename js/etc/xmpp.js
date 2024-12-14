'use strict';
Cryptodog.xmpp = {};
Cryptodog.xmpp.currentStatus = 'online';
Cryptodog.xmpp.connection = null;

$(window).ready(function() {
    let getDefaultServer = function () {
        const mainRelay = 'wss://crypto.dog/websocket';
        const onionRelay = 'ws://doggyhegixd2dvx5bqkxlyqf2pjpu5y72nwiokkn7oegdjpva5ypvyqd.onion/websocket';
        function isOnionService() {
            return window.location.host === new URL(onionRelay).host;
        }
        return {
            name: 'Cryptodog' + (isOnionService() ? ' (Onion Service)' : ''),
            domain: 'crypto.dog',
            conference: 'conference.crypto.dog',
            relay: isOnionService() ? onionRelay : mainRelay,
        };
    };

    Cryptodog.xmpp.defaultServer = getDefaultServer();
    Cryptodog.xmpp.currentServer = {};

    // Load custom server settings
    Cryptodog.storage.getItem('serverName', function(key) {
        Cryptodog.xmpp.currentServer.name = key ? key : Cryptodog.xmpp.defaultServer.name;
    });
    Cryptodog.storage.getItem('domain', function(key) {
        Cryptodog.xmpp.currentServer.domain = key ? key : Cryptodog.xmpp.defaultServer.domain;
    });
    Cryptodog.storage.getItem('conferenceServer', function(key) {
        Cryptodog.xmpp.currentServer.conference = key ? key : Cryptodog.xmpp.defaultServer.conference;
    });
    Cryptodog.storage.getItem('relay', function(key) {
        Cryptodog.xmpp.currentServer.relay = key ? key : Cryptodog.xmpp.defaultServer.relay;
        if (Cryptodog.xmpp.currentServer.relay === 'https://crypto.dog/http-bind') {
            // Hack: the official server no longer supports BOSH, so fall back to WebSocket
            Cryptodog.xmpp.currentServer = Cryptodog.xmpp.defaultServer;
        }
    });


    // Prepares necessary encryption key operations before XMPP connection.
    // Shows a progress bar while doing so.
    Cryptodog.xmpp.showKeyPreparationDialog = function (callback) {
        Cryptodog.me.keyPair = Cryptodog.keys.newKeyPair();
        $('#loginInfo').text(Cryptodog.locale['loginMessage']['generatingKeys']);
        callback();
    }

    // Connect anonymously and join conversation.
    Cryptodog.xmpp.connect = function() {
        Cryptodog.xmpp.connection = new Strophe.Connection(Cryptodog.xmpp.currentServer.relay);

        Cryptodog.xmpp.connection.connect(Cryptodog.xmpp.currentServer.domain, null, function(status) {
            if (status === Strophe.Status.CONNECTING) {
                $('#loginInfo').text(Cryptodog.locale['loginMessage']['connecting']);
            } else if (status === Strophe.Status.CONNECTED) {
                Cryptodog.xmpp.connection.muc.join(
                    Cryptodog.me.conversation + '@' + Cryptodog.xmpp.currentServer.conference,
                    Cryptodog.me.nickname,
                    function(message) {
                        if (Cryptodog.xmpp.onMessage(message)) {
                            return true;
                        }
                    },
                    function(presence) {
                        if (Cryptodog.xmpp.onPresence(presence)) {
                            return true;
                        }
                    }
                );
                Cryptodog.xmpp.onConnected();

                document.title = Cryptodog.me.nickname + '@' + Cryptodog.me.conversationReal;
                $('.conversationName').text(document.title);

                Cryptodog.storage.setItem('nickname', Cryptodog.me.nickname);
            } else if (status === Strophe.Status.DISCONNECTED) {
                if (Cryptodog.loginError) {
                    Cryptodog.xmpp.reconnect();
                }
            }
        });
    };

    // Executes on successfully completed XMPP connection.
    Cryptodog.xmpp.onConnected = function() {
        afterConnect();

        $('#loginInfo').text('✓');
        $('#status').attr('src', 'img/icons/checkmark.svg');
        $('#buddy-groupChat,#status').show();
        $('#buddy-groupChat').insertBefore('#buddiesOnline');
        $('#fill')
            .stop()
            .animate(
                {
                    width: '100%',
                    opacity: '1'
                },
                250,
                'linear'
            );

        window.setTimeout(function() {
            $('#dialogBoxClose').click();
        }, 400);

        window.setTimeout(function() {
            $('#loginOptions,#languages,#customServerDialog').fadeOut(200);
            $('#version,#logoText,#loginInfo,#info,#website,#github').fadeOut(200);
            $('#header').animate({ 'background-color': '#444' });
            $('.logo').animate({ margin: '-11px 5px 0 0' });

            $('#login').fadeOut(200, function() {
                $('#conversationInfo').fadeIn();

                $('#buddy-groupChat').click(function() {
                    Cryptodog.onBuddyClick($(this));
                });

                $('#buddy-groupChat').click();
                $('#conversationWrapper').fadeIn();
                $('#optionButtons').fadeIn();

                $('#footer')
                    .delay(200)
                    .animate({ height: 60 }, function() {
                        $('#userInput').fadeIn(200, function() {
                            $('#userInputText').focus();
                        });
                    });

                $('#buddyWrapper').slideDown();
            });
        }, 800);

        Cryptodog.loginError = true;
    };

    // Reconnect to the same chatroom, on accidental connection loss.
    Cryptodog.xmpp.reconnect = function() {
        // just calling connection.reset() seems to break the muc message and presence handlers
        Cryptodog.xmpp.connection = new Strophe.Connection(Cryptodog.xmpp.currentServer.relay);

        Cryptodog.xmpp.connection.connect(Cryptodog.xmpp.currentServer.domain, null, function(status) {
            if (status === Strophe.Status.CONNECTED) {
                Cryptodog.xmpp.connection.muc.join(
                    Cryptodog.me.conversation + '@' + Cryptodog.xmpp.currentServer.conference,
                    Cryptodog.me.nickname,
                    function(message) {
                        if (Cryptodog.xmpp.onMessage(message)) {
                            return true;
                        }
                    },
                    function(presence) {
                        if (Cryptodog.xmpp.onPresence(presence)) {
                            return true;
                        }
                    }
                );
                afterConnect();
            } else if (status === Strophe.Status.DISCONNECTED) {
                if (Cryptodog.loginError) {
                    $('.conversationName').animate({ 'background-color': '#F00' });
                    window.setTimeout(function() {
                        Cryptodog.xmpp.reconnect();
                    }, 5000);
                }
            }
        });
    };

    // Handle incoming messages from the XMPP server.
    Cryptodog.xmpp.onMessage = async function(message) {
        var nickname = extractNickname($(message).attr('from'));

        var body = $(message)
            .find('body')
            .text();

        var type = $(message).attr('type');

        // If archived message, ignore.
        if ($(message).find('delay').length !== 0) {
            return true;
        }

        // If message is from me, ignore.
        if (nickname === Cryptodog.me.nickname) {
            return true;
        }

        // If message is from someone not on buddy list, ignore.
        if (!Cryptodog.buddies.hasOwnProperty(nickname)) {
            return true;
        }

        // Check if message has a 'composing' notification.
        if ($(message).attr('id') === 'composing' && !body.length) {
            $('#buddy-' + Cryptodog.buddies[nickname].id).addClass('composing');
            return true;
        }

        // Check if message has a 'paused' (stopped writing) notification.
        if ($(message).attr('id') === 'paused') {
            $('#buddy-' + Cryptodog.buddies[nickname].id).removeClass('composing');
        } else if (type === 'groupchat' && body.length) {
            // Check if message is a group chat message.
            $('#buddy-' + Cryptodog.buddies[nickname].id).removeClass('composing');

            try {
                body = await Cryptodog.multiParty.receiveMessage(nickname, Cryptodog.me.nickname, body);
            } catch (e) {
                console.warn('xmpp: exception handling group message from ' + nickname + ': ' + e);
                Cryptodog.UI.messageWarning(nickname, false);
                return true;
            }

            if (typeof body === 'string') {
                Cryptodog.addToConversation(body, nickname, 'groupChat', 'message');
            }
        } else if (type === 'chat') {
            // Check if this is a private OTR message.
            $('#buddy-' + Cryptodog.buddies[nickname].id).removeClass('composing');

            if (body.length > Cryptodog.fileTransfer.maxMessageLength) {
                console.log('xmpp: refusing to decrypt large OTR message (' + body.length + ' bytes) from ' + nickname);
                return true;
            }

            let dm;
            try {
                dm = Cryptodog.multiParty.decryptDirectMessage(body, nickname);
            } catch (e) {
                console.warn(`xmpp: exception handling direct message from ${nickname}: ${e}`);
                Cryptodog.UI.messageWarning(nickname, true);
                return true;
            }

            Cryptodog.addToConversation(dm, nickname, Cryptodog.buddies[nickname].id, 'message');
            if (Cryptodog.me.currentBuddy !== Cryptodog.buddies[nickname].id && !Cryptodog.buddies[nickname].ignored()) {
                Cryptodog.messagePreview(dm, nickname);
            }
        }
        return true;
    };

    // Handle incoming presence updates from the XMPP server.
    Cryptodog.xmpp.onPresence = function(presence) {
        var status;
        var nickname = extractNickname($(presence).attr('from'));

        // If invalid nickname, do not process.
        if ($(presence).attr('type') === 'error') {
            if ($(presence).find('error').attr('code') === '409'
                || $(presence).find('error').find('conflict')) {
                // Delay logout in order to avoid race condition with window animation.
                window.setTimeout(function() {
                    Cryptodog.logout();
                    Cryptodog.UI.loginFail(Cryptodog.locale['loginMessage']['nicknameInUse']);
                }, 3000);

                return false;
            }
            return true;
        }

        if (nickname === Cryptodog.me.nickname) {
            // Unavailable presence from us: we've been kicked, so try to reconnect.
            if ($(presence).attr('type') === 'unavailable') {
                Cryptodog.xmpp.reconnect();
            }

            // Ignore if presence status is coming from myself.
            return true;
        }

        // Detect nickname change (which may be done by non-Cryptodog XMPP clients).
        if (
            $(presence)
                .find('status')
                .attr('code') === '303'
        ) {
            Cryptodog.removeBuddy(nickname);
            return true;
        }

        // Detect buddy going offline.
        if ($(presence).attr('type') === 'unavailable') {
            Cryptodog.removeBuddy(nickname);
            return true;
        } else if (!Cryptodog.buddies.hasOwnProperty(nickname)) {
            // Create buddy element if buddy is new
            Cryptodog.addBuddy(nickname, null, 'online');
            
            // Propagate away status to newcomers.
            Cryptodog.xmpp.sendStatus();
        } else if (
            $(presence)
                .find('show')
                .text() === '' ||
            $(presence)
                .find('show')
                .text() === 'chat'
        ) {
            status = 'online';
        } else {
            status = 'away';
        }

        Cryptodog.buddyStatus(nickname, status);
        return true;
    };

    /* Send our multiparty public key to all room occupants. */
    Cryptodog.xmpp.sendPublicKey = function() {
        Cryptodog.xmpp.connection.muc.message(
            Cryptodog.me.conversation + '@' + Cryptodog.xmpp.currentServer.conference,
            null,
            JSON.stringify(new Cryptodog.multiParty.PublicKey(Cryptodog.me.keyPair.publicKey)),
            null,
            'groupchat',
            'active'
        );
    };

    /* Request public key from `nickname`.
       If `nickname` is omitted, request from all room occupants. */
    Cryptodog.xmpp.requestPublicKey = function(nickname) {
        Cryptodog.xmpp.connection.muc.message(
            Cryptodog.me.conversation + '@' + Cryptodog.xmpp.currentServer.conference,
            null,
            JSON.stringify(new Cryptodog.multiParty.PublicKeyRequest(nickname)),
            null,
            'groupchat',
            'active'
        );
    };

    // Send our current status to the XMPP server.
    Cryptodog.xmpp.sendStatus = function() {
        var status = '';

        if (Cryptodog.xmpp.currentStatus === 'away') {
            status = 'away';
        }

        Cryptodog.xmpp.connection.muc.setStatus(
            Cryptodog.me.conversation + '@' + Cryptodog.xmpp.currentServer.conference,
            Cryptodog.me.nickname,
            status,
            status
        );
    };

    var autoIgnore;

    // Executed (manually) after connection.
    var afterConnect = function() {
        Cryptodog.xmpp.connection.ping.addPingHandler(function(ping) {
            Cryptodog.xmpp.connection.ping.pong(ping);
            return true;
        });

        Cryptodog.xmpp.connection.ibb.addIBBHandler(Cryptodog.fileTransfer.ibbHandler);
        Cryptodog.xmpp.connection.si_filetransfer.addFileHandler(Cryptodog.fileTransfer.fileHandler);

        $('.conversationName').animate({ 'background-color': '#bb7a20' });

        Cryptodog.xmpp.sendStatus();
        Cryptodog.xmpp.sendPublicKey();
        Cryptodog.xmpp.requestPublicKey();

        clearInterval(autoIgnore);

        autoIgnore = setInterval(function() {
            for (var nickname in Cryptodog.buddies) {
                var buddy = Cryptodog.buddies[nickname];
                
                if (Cryptodog.autoIgnore && buddy.messageCount > Cryptodog.maxMessageCount) {
                    buddy.toggleIgnored();
                    console.log('Automatically ignored ' + nickname);
                }

                buddy.messageCount = 0;
            }
        }, Cryptodog.maxMessageInterval);
    };

    // Extract nickname (part after forward slash) from JID
    var extractNickname = function(from) {
        var name = from.match(/\/([\s\S]+)/);

        if (name) {
            return name[1];
        }
        return false;
    };
});
