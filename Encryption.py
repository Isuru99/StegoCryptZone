from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Generating Private & Public Key pairs
def GenerateKeyPair(dir = '', size = 2048):
    # Generating Private Key
    keyPair = RSA.generate(size)
    privateKey = keyPair.export_key()
    with open(dir + '/' + str(size) + 'Private.pem', 'wb') as outputFile:
        outputFile.write(privateKey)

    # Generating Public Key
    publicKey = keyPair.publickey().export_key()
    with open(dir + '/' + str(size) + 'Public.pem', 'wb') as outputFile:
        outputFile.write(publicKey)


def ImportKey(keyPath):
    key = RSA.import_key(open(keyPath, 'rb').read())
    return key

# Encrypting data using RSA encryption method
def EncryptRSA(data, publicKey):
    # Creating objector from PKCS1_OAEP class
    encryptor = PKCS1_OAEP.new(publicKey)
    # if the data is string
    if type(data) == str:
        # Encrypt that string of bytes using utf-8 encoding method
        encrypted = encryptor.encrypt(bytes(data, 'utf-8'))

    elif type(data) == bytes:
        encrypted = encryptor.encrypt(data)

    return encrypted

# Decrypting RSA encryption
def DecryptRSA(encrypted, privateKey):
    decryptor = PKCS1_OAEP.new(privateKey)
    decrypted = decryptor.decrypt(encrypted)
    return decrypted

# Encrypting data using AES encryption method
def EncryptAES(data, publicKeyPath, outputFilePath = None, header = None, size = 16):
    # importing and open the RSA public key
    publicKey = RSA.import_key(open(publicKeyPath).read())
    # Generating random session key
    sessionKey = get_random_bytes(size)
    print(f"Session Key is : {str(sessionKey)}")
    # Encrypting session key using RSA public key
    sessionKeyEncrypted = EncryptRSA(sessionKey, publicKey)
    print(f"Encrypted Session Key is : {str(sessionKeyEncrypted)}")
    # Encrypt the data with the AES session key
    encryptor = AES.new(sessionKey, AES.MODE_GCM)
    if type(header) == str:
        headerLength = str(len(header))
        if len(headerLength) == 1:
            headerLength = '0' + headerLength

        header = bytes(headerLength + header, 'utf-8')

    elif header is None:
        header = bytes('00', 'utf-8')

    encryptor.update(header)
    if type(data) == str:
        ciphertext, tag = encryptor.encrypt_and_digest(bytes(data, 'utf-8'))

    elif type(data) == bytes:
        ciphertext, tag = encryptor.encrypt_and_digest(data)

    if outputFilePath is not None:
        outputFile = open(outputFilePath, 'wb')
        [outputFile.write(x) for x in (header, sessionKeyEncrypted, encryptor.nonce, tag, ciphertext)]
        outputFile.close()

    return header, sessionKeyEncrypted, encryptor.nonce, tag, ciphertext

# Decrypting Data (AES encryption)
def DecryptAES(inputFilePath, privateKeyPath, outputFilePath = None):
    # importing and open the RSA private key
    privateKey = RSA.import_key(open(privateKeyPath).read())
    inputFile = open(inputFilePath, 'rb')
    headerLength = int(inputFile.read(2))
    inputFile.seek(0)
    header, sessionKeyEncrypted, nonce, tag, ciphertext = [inputFile.read(x) for x in (2 + headerLength, privateKey.size_in_bytes(), 16, 16, -1)]

    # Decrypt the session key with the private RSA key
    sessionKey = DecryptRSA(sessionKeyEncrypted, privateKey)
    #print(f"Session Key is : {str(sessionKey)}")

    # Decrypt the data with the AES session key
    decryptor = AES.new(sessionKey, AES.MODE_GCM, nonce)
    decryptor.update(header)
    decrypted = decryptor.decrypt_and_verify(ciphertext, tag)
    if outputFilePath is not None:
        with open(outputFilePath, 'wb') as outputFile:
            outputFile.write(decrypted)

    inputFile.close()
    return decrypted, str(header, 'utf-8')
