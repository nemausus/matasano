# author : Naresh Kumar

from collections import Counter
import string

EN_MOST_FREQUENT = ' etaoin'
EN_AVG_LEN = 4.56
EN_FREQUENCY = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,  # A-G
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,  # H-N
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,  # O-U
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074]                    # V-Z ]

EN_BIGRAMS = {'th':0.0356, 'he':0.0307, 'in':0.0243, 'er':0.0205,
        'an':0.0199, 're':0.0185, 'on':0.0176, 'at':0.0149, 'en':0.0145,
        'nd':0.0135, 'ti':0.0134, 'es':0.0134, 'or':0.0128, 'te':0.0120,
        'of':0.0117, 'ed':0.0117, 'is':0.0113, 'it':0.0112, 'al':0.0109,
        'ar':0.0107, 'st':0.0105, 'to':0.0104, 'nt':0.0104, 'ng':0.0095,
        'se':0.0093, 'ha':0.0093, 'as':0.0087, 'ou':0.0087, 'io':0.0083,
        'le':0.0083, 've':0.0083, 'co':0.0079, 'me':0.0079, 'de':0.0076,
        'hi':0.0076, 'ri':0.0073, 'ro':0.0073, 'ic':0.0070, 'ne':0.0069,
        'ea':0.0069, 'ra':0.0069, 'ce':0.0065, 'li':0.0062, 'ch':0.0060,
        'll':0.0058, 'be':0.0058, 'ma':0.0057, 'si':0.0055, 'om':0.0055,
        'ur':0.0054}

class FrequencyAnalyzer(object):

    @staticmethod
    def GetRepeatingXor(text, key):
        """Sequentially apply xor of each byte of the key to text and repeat"""
        xor = []
        for i, char in enumerate(text):
            key_char = key[i%len(key)]
            xor.append(chr(ord(key_char) ^ ord(char)))
        return ''.join(xor)


    @staticmethod
    def GetChiSquaredError(text):
        """Returns Chi-squared error for english text"""
        text = text.lower()
        frequency = Counter(text)
        error = 0.0
        text_len = len(text)
        alpha = 0
        for c in string.lowercase:
            expected = EN_FREQUENCY[ord(c) - ord('a')]
            observed = frequency[c] / float(text_len)
            error += (expected - observed)**2 / expected
            alpha += frequency[c]

        # Add error for space
        observed = text.count(' ') / float(text_len)
        expected = 1.0 / 1.0 + EN_AVG_LEN
        error += (expected - observed)**2 / expected

        # Add error for non alpha characters
        observed = alpha / float(text_len)
        expected = 0.8
        error += (expected - observed)**2 / expected
        return error


    @staticmethod
    def BreakSingleByteXor(cipher):
        """Breaks single byte xor cipher. Returns (text,key) on success."""
        errors = []
        for key in range(256):
            text = FrequencyAnalyzer.GetRepeatingXor(cipher, chr(key))
            if all(c in string.printable for c in text):
                errors.append((
                    FrequencyAnalyzer.GetChiSquaredError(text), chr(key)))

        if len(errors) == 0:
            return None, None
        else:
            errors.sort()
            key = errors[0][1]
            return FrequencyAnalyzer.GetRepeatingXor(cipher, key), key


    @staticmethod
    def IsEnglish(text):
        """Checks if given ascii text is valid English.
            check 1: all characters should be printable.
            check 2: top 2 most frequent characters shoule be in ' etaoin'
            check 3: at least 90% letters should be in [a-z ]
            check 4: average word length should be in EN_AVG_LEN +-2 range
        """
        text = text.lower()
        # check if all characters are printable
        if not all(c in string.printable for c in text):
            return False
        # check if 2 most common letters in text are among English's most
        # frequent letters.
        frequency = Counter(text)
        if not all(c in EN_MOST_FREQUENT for c,_ in frequency.most_common(2)):
            return False
        # check if at least 90% of letters are among a-z and space.
        myset = 'abcdefghijklmnopqrstuvwxyz '
        count = sum(map(lambda c: 1 if c in myset else 0, text))
        if not count/float(len(text)) > 0.90:
            return False
        # check if average word length in text is close to average word length
        # of English.
        word_len = len(text)/float(len(text.split()))
        diff = abs(word_len - EN_AVG_LEN)
        if diff > 2.0:
            return False
        return True


    @staticmethod
    def GetBigramSquaredError(bigrams):
        """Returns bigram squared error."""
        bigrams = map(lambda b : b.lower(), bigrams)
        frequency = Counter(bigrams)
        error = 0.0
        for bi in Crypto.EN_BIGRAMS:
            expected = EN_BIGRAMS[bi] if bi in EN_BIGRAMS else 0.0
            observed = frequency[bi] / float(len(bigrams))
            error += (expected - observed)**2 / expected
        return error;


    @staticmethod
    def GetBigrams(text):
        words = text.split()
        bigrams = []
        for word in words:
            bigrams.extend([word[i:i+2] for i in range(0, len(word), 2)])
            bigrams.extend([word[i:i+2] for i in range(1, len(word), 2)])
        return filter(lambda bi: len(bi) == 2, bigrams)
