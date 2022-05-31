import os
import PySimpleGUI as sg
import ImgStego as imgstego
import Encryption as crypto
import Audiostego as asg

sg.theme('DarkTeal9')

#Defining tab 1
tab1_layout = [
    [
        sg.Column([
            [sg.Radio("Hybrid Encryption", group_id='aes_rsa_radios', key='aes_radio', default=True, enable_events=True)],
            [sg.Radio("RSA Encryption", group_id='aes_rsa_radios', key='rsa_radio', default=False, enable_events=True)],
            [sg.Radio("Do not use Encryption", group_id='aes_rsa_radios', key='no_encryption_radio', default=False, enable_events=True)],
            [sg.Radio("Audio Steganography", group_id='stego_radios', key='audio_radio', default=True, enable_events=True)],
            [sg.Radio("Image Steganography", group_id='stego_radios', key='image_radio', default=False, enable_events=True)],
            [sg.Radio("Do not use Steganography", group_id='stego_radios', key='no_steganography_radio', default=False, enable_events=True)],

            [sg.Text(text="Output Folder", key='output_fol_heading')],
            [sg.Column([[sg.Input(key='output_fol'), sg.FolderBrowse(key='output_fol_browse')]], key='output_fol_row')],
            [sg.Text(text='', key='output_fol_message', size=(40, 2))],

            [sg.Text(text="Public Key", key='public_key_heading')],
            [sg.Column([[sg.Input(key='public_key', disabled_readonly_background_color='black'), sg.FileBrowse(key='public_key_browse', file_types=(('PEM Files', '*.pem'),))]], key='public_key_row')],
            [sg.Text(text='', key='public_key_message', size=(40, 2))],

            [sg.Text(text="Stego File", key='stego_heading')],
            [sg.Column([[sg.Input(key='stego_file', disabled_readonly_background_color='black'), sg.FileBrowse(key='stego_browse', file_types=(('PNG Files', '*.png'), ('WAV Files', '*.wav')))]], key='stego_row')],
            [sg.Text(text='', key='stego_msg', size=(40, 2))]
        ], vertical_alignment='top'),
        sg.VerticalSeparator(),
        sg.Column([
            [
                sg.Radio("Text", 'text_file_radios', key='text_radio', default=True, enable_events=True),
                sg.Radio("File", 'text_file_radios', key='file_radio', default=False, enable_events=True)
            ],
            [sg.Text(text="File", key='file_heading')],
            [sg.Column([[sg.Input(key='file', disabled_readonly_background_color='black', disabled=True), sg.FileBrowse(key='file_browse', disabled=True)]], key='file_row')],
            [sg.Text(text='', key='secret_message_file', size=(40, 2))],

            [sg.Text(text="Text", key='text_heading')],
            [sg.Multiline(default_text='Type your message here.', size=(40, 15), key='message')],
            [sg.Text(text='', key='secret_message_text', size=(40, 2))],
            [sg.Column([[sg.Button(button_text="Encode", key='data_encryption_button')]])]
        ], vertical_alignment='top')
    ]
]

#Defining tab 2
tab2_layout = [
    [
        sg.Column([
            [sg.Text(text="Encoded or Encrypted File", key='encoded_file_heading')],
            [sg.Column([[sg.Input(key='encoded_file'), sg.FileBrowse(key='encoded_file_browse')]], key='encoded_file_row')],
            [sg.Text(text='', key='encoded_file_message', size=(40, 2))],

            [sg.Text(text="Enter Your Private Key", key='private_key_title')],
            [sg.Column([[sg.Input(key='private_key'), sg.FileBrowse(key='private_key_browse', file_types=(('PEM Files', '*.pem'),))]], key='private_key_row')],
            [sg.Text(text='', key='private_key_message', size=(40, 2))],

            [sg.Text(text="Output Folder", key='decoded_file_output_fol_heading')],
            [sg.Column([[sg.Input(key='decode_file_output_fol', disabled_readonly_background_color='black'), sg.FolderBrowse(key='decode_file_output_fol_browse')]], key='decode_file_output_fol_row')],
            [sg.Text(text='', key='decode_file_output_fol_message', size=(40, 2))]
        ], vertical_alignment='top'),
        sg.VerticalSeparator(),
        sg.Column([
            [sg.Text(text="Secret Message", key='decoded_message_heading')],
            [sg.Multiline(size=(40, 15), disabled=True, key='decoded_message')],
            [sg.Text(text='', key='decode_message', size=(40, 2))],
            [sg.Column([[sg.Button(button_text="Decode", key='decode_button')]])]
        ], vertical_alignment='top')
    ]
]

#Defining tab 3
tab3_layout = [
    [
        sg.Column([
            [sg.Text("Key Size")],
            [sg.Combo(('2048', '3072', '4096'), default_value='3072', key='key_size_combo')],
            [sg.Text("Output Folder")],
            [sg.Column([[sg.Input(key='keys_output_fol'), sg.FolderBrowse(key='keys_output_fol_browse')]], key='keys_output_fol_row')],
            [sg.Text(text='', key='keys_output_fol_message', size=(40, 2))],
            [sg.Button(button_text="Generate keys", key='generate_button')]
        ], vertical_alignment='top')
    ]
]

layout = [
    [
        sg.TabGroup([
            [sg.Tab("Encode", tab1_layout), sg.Tab("Decode", tab2_layout), sg.Tab("Key Generator", tab3_layout)]
        ])
    ]
]

window = sg.Window("SteganoCryptZone", layout)
while True:
    window.refresh()
    event, values = window.read()

    if event == sg.WIN_CLOSED:
        break

# Generating public key and private key
    elif event == 'generate_button':
        if not os.path.exists(values['keys_output_fol']):
            window['keys_output_fol_message'].update("Output Folder not Defined", text_color='red')

        else:
            try:
                crypto.GenerateKeyPair(values['keys_output_fol'], int(values['key_size_combo']))
                window['keys_output_fol_message'].update("Successfully created public and private key pairs", text_color='green')

            except Exception as exception:
                window['keys_output_fol_message'].update("Unable to create public and private key pairs\n" + str(exception), text_color='red')

# Data Encryption and Hiding in Stego Media
    elif event == 'data_encryption_button':
        if not os.path.exists(values['output_fol']):
            window['output_fol_message'].update("Output Folder not Defined", text_color='red')

# Without using any encryption method
        if values['no_encryption_radio'] is False:
            if not os.path.exists(values['public_key']):
                window['public_key_message'].update("Public Key didn't Entered", text_color='red')

# Hiding message in image file or audio file
        if values['image_radio'] or values['audio_radio']:
            if not os.path.exists(values['stego_file']):
                window['stego_msg'].update("Stego File not Given", text_color='red')

        try:
        # Using RSA Encryption with Steganography
            if values['rsa_radio']:

                if values['image_radio'] or values['audio_radio']:
                    if os.path.exists(values['output_fol']) and os.path.exists(values['public_key']) and os.path.exists(values['stego_file']):
                        window['output_fol_message'].update('')
                        window['public_key_message'].update('')
                        window['stego_msg'].update('')

                        # Encrypting text message using RSA encryption
                        if values['text_radio']:
                            publicKey = crypto.ImportKey(values['public_key'])
                            encrypted = 'enct' + str(bytes.hex(crypto.EncryptRSA(values['message'], publicKey)))

                            # Encrypting text message using RSA encryption & Encoding that message inside audio file
                            if values['audio_radio']:
                                asg.AudioEncode(values['stego_file'], encrypted,
                                                values['output_fol'] + '/rsa_song_text_encoded.wav')
                                window['secret_message_text'].update("Successfully Encoded", text_color='green')

                            # Encrypting text message using RSA encryption & Encoding that message inside image file
                            elif values['image_radio']:
                                imgstego.Encode(values['stego_file'], encrypted,
                                                values['output_fol'] + '/rsa_image_text_encoded.png')
                                window['secret_message_text'].update("Successfully Encoded", text_color='green')

                        # Encrypting File using RSA encryption
                        elif values['file_radio']:
                            fileExt = str(values['file']).split('.')[-1].lower()
                            if fileExt.find('/') != -1:
                                fileExt = 'file'

                        fileExtLength = str(len(fileExt))
                        if len(fileExtLength) == 1:
                            fileExtLength = '0' + fileExtLength
                            file = open(values['file'], 'rb').read()
                            publicKey = crypto.ImportKey(values['public_key'])
                            encrypted = 'encf' + str(len(fileExt)) + fileExt + str(
                                bytes.hex(crypto.EncryptRSA(str(file.hex()), publicKey)))

                            # Encrypting file using RSA encryption & Encoding that file inside audio file
                            if values['audio_radio']:
                                asg.AudioEncode(values['stego_file'], encrypted,
                                                values['output_fol'] + '/rsa_song_file_encoded.wav')
                                window['secret_message_text'].update("Successfully Encoded", text_color='green')

                            # Encrypting file using RSA encryption & Encoding that file inside image file
                            elif values['image_radio']:
                                imgstego.Encode(values['stego_file'], encrypted,
                                                values['output_fol'] + '/rsa_image_file_encoded.png')
                                window['secret_message_text'].update("Successfully Encoded", text_color='green')

            # Using Hybrid Encryption with Steganography
            elif values['aes_radio']:

                if values['image_radio'] or values['audio_radio']:
                    if os.path.exists(values['output_fol']) and os.path.exists(values['public_key']) and os.path.exists(
                            values['stego_file']):
                        window['output_fol_message'].update('')
                        window['public_key_message'].update('')
                        window['stego_msg'].update('')

                        # Encrypting text message using Hybrid encryption
                        if values['text_radio']:
                            header, sessionKeyEncrypted, nonce, tag, ciphertext = crypto.EncryptAES(values['message'],
                                                                                                    values[
                                                                                                        'public_key'],
                                                                                                    header='enc_text_aes')

                            # Encrypting text message using Hybrid encryption & Encoding that message inside audio file
                            if values['audio_radio']:
                                asg.AudioEncode(values['stego_file'],
                                                bytes.hex(header) + bytes.hex(sessionKeyEncrypted) + bytes.hex(
                                                    nonce) + bytes.hex(tag) + bytes.hex(ciphertext),
                                                values['output_fol'] + '/aes_song_text_encoded.wav')
                                window['secret_message_text'].update("Successfully Encoded", text_color='green')

                            # Encrypting text message using Hybrid encryption & Encoding that message inside image file
                            else:
                                imgstego.Encode(values['stego_file'],
                                                bytes.hex(header) + bytes.hex(sessionKeyEncrypted) + bytes.hex(
                                                    nonce) + bytes.hex(tag) + bytes.hex(ciphertext),
                                                values['output_fol'] + '/aes_image_text_encoded.png')
                                window['secret_message_text'].update("Successfully Encoded", text_color='green')

                        # Encrypting File using Hybrid encryption
                        elif values['file_radio']:
                            fileExt = str(values['file']).split('.')[-1].lower()
                            if fileExt.find('/') != -1:
                                fileExt = 'file'

                            file = open(values['file'], 'rb').read()
                            header, sessionKeyEncrypted, nonce, tag, ciphertext = crypto.EncryptAES(bytes.hex(file),
                                                                                                    values[
                                                                                                        'public_key'],
                                                                                                    header='enc_file_aes_' + fileExt)
                            # Encrypting file using Hybrid encryption & Encoding that file inside audio file
                            if values['audio_radio']:
                                asg.AudioEncode(values['stego_file'],
                                                bytes.hex(header) + bytes.hex(sessionKeyEncrypted) + bytes.hex(
                                                    nonce) + bytes.hex(tag) + bytes.hex(ciphertext),
                                                values['output_fol'] + '/aes_song_file_encoded.wav')
                                window['secret_message_text'].update("Successfully Encoded", text_color='green')

                            # Encrypting file using Hybrid encryption & Encoding that file inside image file
                            elif values['image_radio']:
                                imgstego.Encode(values['stego_file'],
                                                bytes.hex(header) + bytes.hex(sessionKeyEncrypted) + bytes.hex(
                                                    nonce) + bytes.hex(tag) + bytes.hex(ciphertext),
                                                values['output_fol'] + '/aes_image_file_encoded.png')
                                window['secret_message_text'].update("Successfully Encoded", text_color='green')

            # Steganography without using encryption
            elif values['no_encryption_radio'] and (values['image_radio'] or values['audio_radio']):

                if os.path.exists(values['stego_file']):
                    window['output_fol_message'].update('')
                    window['stego_msg'].update('')

                    if values['text_radio']:

                        # Text message hide inside audio file
                        if values['audio_radio']:
                            asg.AudioEncode(values['stego_file'], 'plnt' + values['message'],
                                            values['output_fol'] + '/song_text_encoded.wav')
                            window['secret_message_text'].update("Successfully encrypted", text_color='green')

                        # Text message hide inside image file
                        elif values['image_radio']:
                            imgstego.Encode(values['stego_file'], 'plnt' + values['message'],
                                            values['output_fol'] + '/image_text_encoded.png')
                            window['secret_message_text'].update("Successfully Encoded", text_color='green')

                    # File hide inside image
                    elif values['file_radio']:
                        fileExt = str(values['file']).split('.')[-1].lower()
                        if fileExt.find('/') != -1:
                            fileExt = 'file'

                        file = open(values['file'], 'rb').read()

                        # File hide inside audio file
                        if values['audio_radio']:
                            asg.AudioEncode(values['stego_file'],
                                            'plnf' + str(len(fileExt)) + fileExt + bytes.hex(file),
                                            values['output_fol'] + '/song_file_encoded.wav')
                            window['secret_message_text'].update("Successfully Encoded", text_color='green')

                        # File hide inside image file
                        elif values['image_radio']:
                            imgstego.Encode(values['stego_file'],
                                            'plnf' + str(len(fileExt)) + fileExt + bytes.hex(file),
                                            values['output_fol'] + '/image_file_encoded.png')
                            window['secret_message_text'].update("Successfully Encoded", text_color='green')

        # Encryption without using steganography
            if values['no_steganography_radio'] and (values['rsa_radio'] or values['aes_radio']):

                if os.path.exists(values['output_fol']) and os.path.exists(values['public_key']):
                    window['output_fol_message'].update('')
                    window['public_key_message'].update('')

                    # Using RSA Encryption without using Steganography
                    if values['rsa_radio']:

                        # Encrypting text message using RSA encryption
                        if values['text_radio']:
                            with open(values['output_fol'] + '/encrypted', 'wb') as outputFile:
                                publicKey = crypto.ImportKey(values['public_key'])
                                outputFile.write(b'enct' + crypto.EncryptRSA(values['message'], publicKey))
                                window['secret_message_text'].update("Successfully Done", text_color='green')

                        # Encrypting File using RSA encryption
                        elif values['file_radio']:
                            with open(values['output_fol'] + '/encrypted', 'wb') as outputFile:
                                fileExt = str(values['file']).split('.')[-1].lower()
                                if fileExt.find('/') != -1:
                                    fileExt = 'file'

                                fileExtLength = str(len(fileExt))
                                if len(fileExtLength) == 1:
                                    fileExtLength = '0' + fileExtLength
                                    file = open(values['file'], 'rb').read()
                                    publicKey = crypto.ImportKey(values['public_key'])
                                    outputFile.write(b'encf' + bytes(fileExtLength, 'utf-8') + bytes(fileExt,
                                                                                                     'utf-8') + crypto.EncryptRSA(
                                        str(file.hex()), publicKey))
                                    window['secret_message_text'].update("Successfully Encrypted", text_color='green')

                    # Using AES Encryption without using Steganography
                    elif values['aes_radio']:

                        # Encrypting text message using Hybrid encryption
                        if values['text_radio']:
                            with open(values['output_fol'] + '/encrypted', 'wb') as outputFile:
                                crypto.EncryptAES(values['message'], values['public_key'],
                                                  values['output_fol'] + '/encrypted', 'enc_text_aes')
                                window['secret_message_text'].update("Successfully Done", text_color='green')

                        # Encrypting File using Hybrid encryption
                        elif values['file_radio']:
                            with open(values['output_fol'] + '/encrypted', 'wb') as outputFile:
                                fileExt = str(values['file']).split('.')[-1].lower()
                                if fileExt.find('/') != -1:
                                    fileExt = 'file'

                                file = open(values['file'], 'rb').read()
                                crypto.EncryptAES(bytes.hex(file), values['public_key'],
                                                  values['output_fol'] + '/encrypted', 'enc_file_aes_' + fileExt)
                                window['secret_message_text'].update("Successfully Encoded", text_color='green')


        except Exception as exception:
            window['secret_message_text'].update("Unable to Encode\n" + str(exception), text_color='red')

    # Data Decryption and Decoding in Stego Media
    elif event == 'decode_button':
        if not os.path.exists(values['encoded_file']):
            window['encoded_file_message'].update("Invalid file", text_color='red')

        # try sequence->
        # if wav->audioDecode, if png->imageDecode, if not (wav or png)-> try both, if all above fails -> error
        try:
            # decode wav files
            if str(values['encoded_file']).split('.')[-1].lower() == 'wav':

                # Decoding Audio File Without encryption (Text)
                if os.path.exists(values['encoded_file']):
                    window['encoded_file_message'].update('')
                    window['private_key_message'].update('')
                    file = asg.AudioDecode(values['encoded_file'])
                    try:
                        filefromhex = bytes.fromhex(file)

                    except Exception:
                        filefromhex = file

                    if file[0:4] == 'plnt':
                        window['decoded_message'].update(file[4:])
                        window['decode_message'].update('Successfully Decoded File 1', text_color='green')

                    # Decoding Audio File Without encryption (File)
                    elif file[0:4] == 'plnf':
                        fileExtLength = int(file[4])
                        fileExt = file[5:(5 + fileExtLength)]
                        with open(values['decode_file_output_fol'] + '/Secret File' + fileExt, 'wb') as outputFile:
                            outputFile.write(bytes.fromhex(file[(5 + fileExtLength):]))

                        try:
                            window['decoded_message'].update("Saved Decoded Data on File. Contents:\n\n" + str(
                                bytes.fromhex(file[(5 + fileExtLength):]), 'utf-8'))

                        except Exception:
                            window['decoded_message'].update("Saved Decoded Data on File.")

                        window['decode_message'].update("Successfully Decoded File 2", text_color='green')

                    # Decoding With RSA encryption Audio Files (Text)
                    elif not os.path.exists(values['private_key']):
                        window['private_key_message'].update("Private Key Didn't Entered", text_color='red')

                    elif os.path.exists(values['private_key']):
                        privateKey = crypto.ImportKey(values['private_key'])
                        if file[0:4] == 'enct':
                            decrypted = str(crypto.DecryptRSA(bytes.fromhex(file[4:]), privateKey), 'utf-8')
                            window['decoded_message'].update(decrypted)
                            window['decode_message'].update("Successfully Decoded File 3", text_color='green')

                        elif not os.path.exists(values['decode_file_output_fol']):
                            window['decode_file_output_fol_message'].update("Output Folder not Define", text_color='red')

                        # Decoding With Hybrid encryption audio files (Text)
                        elif type(filefromhex) == bytes:
                            if str(filefromhex[0:14], 'utf-8') == '12enc_text_aes':
                                with open(values['decode_file_output_fol'] + '/aes_text_fromhex_temp', 'wb') as tempFile:
                                    tempFile.write(filefromhex)

                                decrypted, header = crypto.DecryptAES(
                                    values['decode_file_output_fol'] + '/aes_text_fromhex_temp', values['private_key'])
                                os.remove(values['decode_file_output_fol'] + '/aes_text_fromhex_temp')
                                window['decoded_message'].update(str(decrypted, 'utf-8'))
                                window['decode_message'].update("Successfully Decrypted file 4", text_color='green')

                            # Decoding With Hybrid Encryption audio files (File)
                            elif str(filefromhex[0:14], 'utf-8').find('enc_file_aes') != -1:
                                with open(values['decode_file_output_fol'] + '/aes_file_fromhex_temp', 'wb') as tempFile:
                                    tempFile.write(filefromhex)

                                decrypted, header = crypto.DecryptAES(
                                    values['decode_file_output_fol'] + '/aes_file_fromhex_temp', values['private_key'])
                                fileExt = header[15:]
                                with open(values['decode_file_output_fol'] + '/Decoded.' + fileExt, 'wb') as outputFile:
                                    outputFile.write(bytes.fromhex(str(decrypted, 'utf-8')))

                                try:
                                    window['decoded_message'].update(
                                        "Saved Decoded Data File. Contents:\n\n" + str(
                                            bytes.fromhex(str(decrypted, 'utf-8')), 'utf-8'))

                                except Exception:
                                    window['decoded_message'].update("Saved Decoded Data File.")

                                os.remove(values['decode_file_output_fol'] + '/aes_file_fromhex_temp')
                                window['decode_message'].update("Successfully Decoded File 5", text_color='green')

                        # Decoding With RSA encryption Audio Files (File) Some errors have to fix in future
                        elif str(file[0:4], 'utf-8') == 'encf':
                            fileExtLength = int(file[4] + file[5])
                            fileExt = file[6:(6 + fileExtLength)]
                            decrypted = str(bytes.fromhex(
                                str(crypto.DecryptRSA(bytes.fromhex(file[(6 + fileExtLength):]), privateKey), 'utf-8')),
                                            'utf-8')
                            with open(values['decode_file_output_fol'] + '/Decoded Secret Text File.' + fileExt, 'wb') as outputFile:
                                outputFile.write(bytes(decrypted, 'utf-8'))

                            try:
                                window['decoded_message'].update(
                                    "Saved Decrypted Data to file. Contents:\n\n" + decrypted)

                            except Exception:
                                window['decoded_message'].update("Saved Decrypted Data to file.")

                            window['decode_message'].update("Successfully Decoded File 6", text_color='green')

                    else:
                        window['decoded_message'].update('')
                        window['decode_message'].update("Unable to Decrypt or Decode file\n" + "unknown file", text_color='red')

            # Decode PNG Files
            elif str(values['encoded_file']).split('.')[-1].lower() == 'png':

                # Decoding Image Files Without encryption (Text)
                if os.path.exists(values['encoded_file']):
                    window['encoded_file_message'].update('')
                    window['private_key_message'].update('')
                    file = imgstego.Decode(values['encoded_file'])
                    try:
                        filefromhex = bytes.fromhex(file)

                    except Exception:
                        filefromhex = file

                    if file[0:4] == 'plnt':
                        window['decoded_message'].update(file[4:])
                        window['decode_message'].update('Successfully Decoded File 7', text_color='green')

                    # Decoding Image File Without encryption (File)
                    elif file[0:4] == 'plnf':
                        fileExtLength = int(file[4])
                        fileExt = file[5:(5 + fileExtLength)]
                        with open(values['decode_file_output_fol'] + '/Decoded Secret Text.' + fileExt, 'wb') as outputFile:
                            outputFile.write(bytes.fromhex(file[(5 + fileExtLength):]))

                        try:
                            window['decoded_message'].update("Saved Decoded Data on File. Contents:\n\n" + str(
                                bytes.fromhex(file[(5 + fileExtLength):]), 'utf-8'))

                        except Exception:
                            window['decoded_message'].update("Saved Decoded Data on File.")

                        window['decode_message'].update("Successfully Decoded File", text_color='green')

                    elif not os.path.exists(values['private_key']):
                        window['private_key_message'].update("Please Enter Correct Private Key", text_color='red')

                    # Decoding With RSA encryption Image Files (Text)
                    elif os.path.exists(values['private_key']):
                        privateKey = crypto.ImportKey(values['private_key'])
                        if file[0:4] == 'enct':
                            decrypted = str(crypto.DecryptRSA(bytes.fromhex(file[4:]), privateKey), 'utf-8')
                            window['decoded_message'].update(decrypted)
                            window['decode_message'].update("Successfully Decoded File", text_color='green')

                        elif not os.path.exists(values['decode_file_output_fol']):
                            window['decode_file_output_fol_message'].update("Output Folder not Defined", text_color='red')

                        # Decoding With Hybrid encryption Image Files (Text)
                        elif type(filefromhex) == bytes:
                            if str(filefromhex[0:14], 'utf-8') == '12enc_text_aes':
                                with open(values['decode_file_output_fol'] + '/aes_text_fromhex_temp', 'wb') as tempFile:
                                    tempFile.write(filefromhex)

                                decrypted, header = crypto.DecryptAES(
                                    values['decode_file_output_fol'] + '/aes_text_fromhex_temp', values['private_key'])
                                os.remove(values['decode_file_output_fol'] + '/aes_text_fromhex_temp')
                                window['decoded_message'].update(str(decrypted, 'utf-8'))
                                window['decode_message'].update("Successfully Decoded File 8", text_color='green')

                            # Decoding With Hybrid encryption Image Files (File)
                            elif str(filefromhex[0:14], 'utf-8').find('enc_file_aes') != -1:
                                with open(values['decode_file_output_fol'] + '/aes_file_fromhex_temp', 'wb') as tempFile:
                                    tempFile.write(filefromhex)

                                decrypted, header = crypto.DecryptAES(
                                    values['decode_file_output_fol'] + '/aes_file_fromhex_temp', values['private_key'])
                                fileExt = header[15:]
                                with open(values['decode_file_output_fol'] + '/Decoded Secret Text File.' + fileExt, 'wb') as outputFile:
                                    outputFile.write(bytes.fromhex(str(decrypted, 'utf-8')))

                                try:
                                    window['decoded_message'].update(
                                        "Decoded Data saved to File. Contents:\n\n" + str(
                                            bytes.fromhex(str(decrypted, 'utf-8')), 'utf-8'))

                                except Exception:
                                    window['decoded_message'].update("Decoded Data saved to File.")

                                os.remove(values['decode_file_output_fol'] + '/aes_file_fromhex_temp')
                                window['decode_message'].update("Successfully Decoded File 9", text_color='green')

                        # Decoding With RSA encryption Image Files (File) Some errors have to fix in future
                        elif str(file[0:4], 'utf-8') == 'encf':
                            fileExtLength = int(file[4] + file[5])  # RSA_ERROR
                            fileExt = file[6:(6 + fileExtLength)]
                            decrypted = str(bytes.fromhex(
                                str(crypto.DecryptRSA(bytes.fromhex(file[(6 + fileExtLength):]), privateKey), 'utf-8')),
                                            'utf-8')
                            with open(values['decode_file_output_fol'] + '/Decoded Secret Text File.' + fileExt, 'wb') as outputFile:
                                outputFile.write(bytes(decrypted, 'utf-8'))

                            try:
                                window['decoded_message'].update(
                                    "Decoded Data saved to File. Contents:\n\n" + decrypted)

                            except Exception:
                                window['decoded_message'].update("Saved decrypted data to file.")

                            window['decode_message'].update("Successfully Decoded File 10", text_color='green')

                    else:
                        window['decoded_message'].update('')
                        window['decode_message'].update("Unable to decrypt file 2\n" + "unknown file",
                                                         text_color='red')

            # Decrypting encrypted files (no Steganography used)
            elif (str(values['encoded_file']).split('.')[-1].lower() != 'wav' or
                  str(values['encoded_file']).split('.')[-1].lower() != 'png'):

                if not os.path.exists(values['private_key']):
                    window['private_key_message'].update("Please Enter Correct Private Key", text_color='red')

                else:
                    privateKey = crypto.ImportKey(values['private_key'])
                    file = open(values['encoded_file'], 'rb').read()

                    # Decrypting RSA encryption (Text)
                    if str(file[0:4], 'utf-8') == 'enct':
                        decrypted = str(crypto.DecryptRSA(file[4:], privateKey), 'utf-8')
                        window['decoded_message'].update(decrypted)
                        window['decode_message'].update("Successfully Decrypted File 11", text_color='green')

                    # Decrypting Hybrid encryption (Text)
                    elif str(file[0:4], 'utf-8') == '12en':
                        if str(file[0:14], 'utf-8') == '12enc_text_aes':
                            decrypted, header = crypto.DecryptAES(values['encoded_file'], values['private_key'])
                            window['decoded_message'].update(str(decrypted, 'utf-8'))
                            window['decode_message'].update("Successfully Decrypted File 12", text_color='green')

                    elif not os.path.exists(values['decode_file_output_fol']):
                        window['decode_file_output_fol_message'].update("Output Folder not Defined", text_color='red')

                    # Decrypting RSA encryption (File)
                    elif str(file[0:4], 'utf-8') == 'encf':
                        fileExtLength = int(chr(file[4]) + chr(file[5]))
                        fileExt = str(file[6:(6 + fileExtLength)], 'utf-8')
                        decrypted = str(
                            bytes.fromhex(str(crypto.DecryptRSA(file[(6 + fileExtLength):], privateKey), 'utf-8')),
                            'utf-8')
                        with open(values['decode_file_output_fol'] + '/Decrypted Secret Text file.' + fileExt, 'wb') as outputFile:
                            outputFile.write(bytes(decrypted, 'utf-8'))

                        try:
                            window['decoded_message'].update(
                                "Decrypted Data saved to file. Contents:\n\n" + decrypted)

                        except Exception:
                            window['decoded_message'].update("Decrypted Data saved to file.")

                        window['decode_message'].update("Successfully Decrypted File 13", text_color='green')

                    # Decrypting Hybrid encryption (File)
                    elif str(file[0:14], 'utf-8').find('enc_file_aes') != -1:
                        decrypted, header = crypto.DecryptAES(values['encoded_file'], values['private_key'])
                        fileExt = header[15:]
                        with open(values['decode_file_output_fol'] + '/decrypted.' + fileExt, 'wb') as outputFile:
                            outputFile.write(bytes.fromhex(str(decrypted, 'utf-8')))

                        try:
                            window['decoded_message'].update("Decrypted Data saved to file. Contents:\n\n" + str(
                                bytes.fromhex(str(decrypted, 'utf-8')), 'utf-8'))

                        except Exception:
                            window['decoded_message'].update("Decrypted Data saved to file.")

                        window['decode_message'].update("Successfully Decrypted File 14", text_color='green')

                    else:
                        window['decoded_message'].update('')
                        window['decode_message'].update("Unable to decrypt file 1\n" + "unknown file",
                                                         text_color='red')


        except Exception as exception:
            print(exception)
            window['decoded_message'].update('')
            window['decode_message'].update("Unable to Decrypt File 3\n" + str(exception), text_color='red')

    if values['text_radio']:
        window['message'].update(disabled=False)
        window['message'].Widget.config(bg='#4D4D4D')
        window['file'].update(disabled=True)
        window['file_browse'].update(disabled=True)

    elif values['file_radio']:
        window['message'].update(disabled=True)
        window['message'].Widget.config(bg='#000000')
        window['file'].update(disabled=False)
        window['file_browse'].update(disabled=False)

    if values['no_steganography_radio']:
        window['no_encryption_radio'].update(False, disabled=True),
        window['stego_file'].update(disabled=True)
        window['stego_browse'].update(disabled=True)
        window['public_key'].update(disabled=False)
        window['public_key_browse'].update(disabled=False)


    elif not values['no_steganography_radio']:
        window['stego_file'].update(disabled=False)
        window['stego_browse'].update(disabled=False)
        window['public_key'].update(disabled=False)
        window['public_key_browse'].update(disabled=False)
        window['no_encryption_radio'].update(disabled=False)

    if values['no_encryption_radio']:
        window['no_steganography_radio'].update(False, disabled=True)
        window['stego_file'].update(disabled=False)
        window['stego_browse'].update(disabled=False)
        window['public_key'].update(disabled=True)
        window['public_key_browse'].update(disabled=True)

    elif not values['no_encryption_radio']:
        window['image_radio'].update(disabled=False)
        window['audio_radio'].update(disabled=False)
        window['stego_file'].update(disabled=False)
        window['stego_browse'].update(disabled=False)
        window['public_key'].update(disabled=False)
        window['public_key_browse'].update(disabled=False)
        window['no_steganography_radio'].update(disabled=False)

window.close()
