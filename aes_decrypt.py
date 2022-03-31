import base64
from Crypto.Cipher import AES

AES256_KEY = "c2l0ZV8yOTQ0XnZlcl8xLjBeT1NQQ0Je"


class AESCipher(object):
    def __init__(self, key):
        self.bs = 32
        self.PADDING = "#".encode('utf8')
        self.key = key[:32]
        self.IV = '\x00'.encode('utf8') * 16

    def encrypt(self, raw):
        raw = self._pad(raw.encode('utf8'))
        iv = self.IV
        cipher = AES.new(self.key.encode('utf8'), AES.MODE_CBC, iv)
        return base64.b64encode(cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = self.IV
        cipher = AES.new(self.key.encode('utf8'), AES.MODE_CBC, iv)
        return cipher.decrypt(enc).rstrip(bytes(self.PADDING))

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * self.PADDING

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]


def aes256cbc_decrypt(rawdata):
    a = AESCipher(AES256_KEY)
    decrypt_data = a.decrypt(rawdata)
    print(decrypt_data.decode('utf8'))


if __name__ == "__main__":
    aes256cbc_decrypt("2tgMhR2yM2OpdbeNhZ0iU+s0Jf9BsPES+HfBWEkRh6A=")
