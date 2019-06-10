import nacl.encoding
import nacl.signing

signing_key = nacl.signing.SigningKey.generate()

signed = signing_key.sign(b"Suit Up")

verify_key = signing_key.verify_key

verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)