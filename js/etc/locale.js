(function() {
    'use strict';

    Cryptodog.locale = {};
    var languageObject;

    Cryptodog.locale.set = function(locale, refresh) {
        Cryptodog.locale.buildObject(locale, refresh);
    };

    // alternate async JSON-based language object builder
    Cryptodog.locale.buildObject = function(locale, refresh) {
        log('Locale builder invoked');

        // make locale lowercase
        locale = locale.toLowerCase();

        // get a list of available languages
        $.getJSON('lang/langlist.json', function(langlist) {
            log('Got langlist');

            // handle aliases
            if (langlist['aliases'].hasOwnProperty(locale)) {
                var newlang = langlist['aliases'][locale];
                log(locale + ' -> ' + newlang);
                locale = newlang;
            }

            // make sure language is enabled
            if (langlist['languages'].indexOf(locale) === -1) {
                // language not present, default to en-US
                console.warn("Locale '" + locale + "' was not found, defaulting to en-US.");
                locale = 'en-us';
            } else {
                log("Locale '" + locale + "' found, loading.");
            }

            $.getJSON('lang/' + locale + '.json', function(data) {
                log("Got language file '" + locale + "'");
                for (var o in data) {
                    if (data.hasOwnProperty(o)) {
                        Cryptodog.locale[o] = data[o];
                    }
                }
                
                log(refresh ? 'Caller requested refresh' : 'Caller did not request refresh');
                if (refresh) Cryptodog.locale.refresh(data);
            });
        });
    };

    // Re-render login page with new strings
    Cryptodog.locale.refresh = function(languageObject) {
        var smallType = ['bo', 'ar', 'in'];
        
        if (smallType.indexOf(languageObject['language']) >= 0) {
            $('body').css({ 'font-size': '13px' });
        } else {
            $('body').css({ 'font-size': '11px' });
        }
        
        $('body').css('font-family', languageObject['fonts']);
        $('#introHeader').text(languageObject['loginWindow']['introHeader']);
        $('#introParagraph').html(languageObject['loginWindow']['introParagraph']);
        $('#customServer').text(languageObject['loginWindow']['customServer']);
        $('#conversationName').attr('placeholder', languageObject['loginWindow']['conversationName']);
        $('#conversationName').attr('data-utip', languageObject['loginWindow']['conversationNameTooltip']);
        $('#nickname').attr('placeholder', languageObject['loginWindow']['nickname']);
        $('#loginSubmit').val(languageObject['loginWindow']['connect']);
        $('#logout').attr('data-utip', languageObject['chatWindow']['logout']);
        $('#audio').attr('data-utip', languageObject['chatWindow']['audioNotificationsOff']);
        $('#notifications').attr('data-utip', languageObject['chatWindow']['desktopNotificationsOff']);
        $('#myInfo').attr('data-utip', languageObject['chatWindow']['myInfo']);
        $('#status').attr('data-utip', languageObject['chatWindow']['statusAvailable']);
        
        $('#buddy-groupChat')
            .find('span')
            .text(languageObject['chatWindow']['conversation']);
        
        $('#languageSelect').text($('[data-locale=' + languageObject['language'] + ']').text());
        $('[data-login=cryptocat]').text(languageObject.login.groupChat);
        $('[data-utip]').utip();
        $('html').attr('dir', languageObject['direction']);
        
        if (languageObject['direction'] === 'ltr') {
            $('div#bubble #info li').css('background-position', 'top left');
        } else {
            $('div#bubble #info li').css('background-position', 'top right');
        }
        
        $('#conversationName').select();
    };

    // Populate language
    if (typeof window !== 'undefined') {
        $(window).ready(function() {
            log('Window ready, loading default language');
            Cryptodog.locale.set('en-US', true);
        });
    }
})();
