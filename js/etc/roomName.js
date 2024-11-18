// Generate random, pronounceable room names
// Based on https://github.com/lpar/kpwgen and https://shorl.com/koremutake.php

Cryptodog.roomName = function () {
    const numSyllables = 12;
    const separator = '-';

    const syllables = ['ba', 'be', 'bi', 'bo', 'bu', 'by', 'da', 'de', 'di', 'do', 'du', 'dy', 'fe', 'fi', 'fo', 'fu', 'fy', 'ga', 'ge', 'gi', 'go', 'gu', 'gy', 'ha', 'he', 'hi', 'ho', 'hu', 'hy', 'ja', 'je', 'ji', 'jo', 'ju', 'jy', 'ka', 'ke', 'ko', 'ku', 'ky', 'la', 'le', 'li', 'lo', 'lu', 'ly', 'ma', 'me', 'mi', 'mo', 'mu', 'my', 'na', 'ne', 'ni', 'no', 'nu', 'ny', 'pa', 'pe', 'pi', 'po', 'pu', 'py', 'ra', 're', 'ri', 'ro', 'ru', 'ry', 'sa', 'se', 'si', 'so', 'su', 'sy', 'ta', 'te', 'ti', 'to', 'tu', 'ty', 'va', 've', 'vi', 'vo', 'vu', 'vy', 'bra', 'bre', 'bri', 'bro', 'bru', 'bry', 'dra', 'dre', 'dri', 'dro', 'dru', 'dry', 'fra', 'fre', 'fri', 'fro', 'fru', 'fry', 'gra', 'gre', 'gri', 'gro', 'gru', 'gry', 'pra', 'pre', 'pri', 'pro', 'pru', 'pry', 'sta', 'ste', 'sti', 'sto', 'stu', 'sty', 'tra', 'tre', 'er', 'ed', 'in', 'ex', 'al', 'en', 'an', 'ad', 'or', 'at', 'ca', 'ap', 'el', 'ci', 'et', 'it', 'ob', 'of', 'af', 'au', 'cy', 'im', 'op', 'co', 'up', 'ing', 'con', 'ter', 'com', 'per', 'ble', 'der', 'cal', 'man', 'est', 'for', 'mer', 'col', 'ful', 'get', 'low', 'son', 'tle', 'day', 'pen', 'ten', 'tor', 'ver', 'ber', 'can', 'ple', 'fer', 'gen', 'den', 'mag', 'sub', 'sur', 'men', 'min', 'out', 'tal', 'but', 'cit', 'cle', 'cov', 'dif', 'ern', 'eve', 'hap', 'ket', 'nal', 'sup', 'ted', 'tem', 'tin', 'tro'];

    if (syllables.length > 256) {
        throw new Error('syllables list too large for RNG');
    }

    function generate() {
        let name = '';

        for (let i = 0; i < numSyllables; i++) {
            if (i > 0 && i % 3 == 0) {
                name += separator;
            }

            // select a syllable without bias
            let rand;
            do {
                rand = randByte();
            } while (rand >= syllables.length);

            const s = syllables[rand];
            name += s;
        }
        return name;
    }

    function randByte() {
        const array = new Uint8Array(1);
        crypto.getRandomValues(array);
        return array[0];
    }

    return {
        generate
    };
}();
