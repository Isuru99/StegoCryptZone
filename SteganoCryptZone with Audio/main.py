import os
import PySimpleGUI as sg
import crypto
import AudioStego as stego

sg.theme('DarkTeal9')

#Defining tab 1
tab1_layout = [
    [
        sg.Column([
            [sg.Radio("AES Encryption", group_id='aes_rsa_radios', key='aes_radio', default=True, enable_events=True)],
            [sg.Radio("RSA Encryption", group_id='aes_rsa_radios', key='rsa_radio', default=False, enable_events=True)],
            [sg.Radio("Do not encrypt", group_id='aes_rsa_radios', key='no_encryption_radio', default=False, enable_events=True)],
            [sg.Checkbox("Hide data inside audio", key='audio_checkbox', default=True, enable_events=True)],

            [sg.Text(text="Output folder", key='output_fol_heading')],
            [sg.Column([[sg.Input(key='output_fol'), sg.FolderBrowse(key='output_fol_browse')]], key='output_fol_row')],
            [sg.Text(text='', key='output_fol_message', size=(40, 2))],

            [sg.Text(text="Public key", key='public_key_heading')],
            [sg.Column([[sg.Input(key='public_key', disabled_readonly_background_color='black'), sg.FileBrowse(key='public_key_browse', file_types=(('PEM Files', '*.pem'),))]], key='public_key_row')],
            [sg.Text(text='', key='public_key_msg', size=(40, 2))],

            [sg.Text(text="Audio file", key='audio_heading')],
            [sg.Column([[sg.Input(key='audio_file', disabled_readonly_background_color='black'), sg.FileBrowse(key='audio_browse', file_types=(('WAV Files', '*.wav'),))]], key='audio_row')],
            [sg.Text(text='', key='audio_msg', size=(40, 2))]
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
            [sg.Text(text="Encrypted file", key='encrypted_file_heading')],
            [sg.Column([[sg.Input(key='encrypted_file'), sg.FileBrowse(key='encrypted_file_browse')]], key='encrypted_file_row')],
            [sg.Text(text='', key='encrypted_message_file', size=(40, 2))],

            [sg.Text(text="Enter Your Private Key", key='private_key_title')],
            [sg.Column([[sg.Input(key='private_key'), sg.FileBrowse(key='private_key_browse', file_types=(('PEM Files', '*.pem'), ))]], key='private_key_row')],
            [sg.Text(text='', key='private_key_message', size=(40, 2))],

            [sg.Text(text="Output folder", key='decrypt_file_output_fol_heading')],
            [sg.Column([[sg.Input(key='decrypt_file_output_fol', disabled_readonly_background_color='black'), sg.FolderBrowse(key='decrypt_file_output_fol_browse')]], key='decrypt_file_output_fol_row')],
            [sg.Text(text='', key='decrypt_file_output_fol_message', size=(40, 2))]
        ], vertical_alignment='top'),
        sg.VerticalSeparator(),
        sg.Column([
            [sg.Text(text="Text", key='decrypted_message_heading')],
            [sg.Multiline(size=(40, 15), disabled=True, key='decrypted_message')],
            [sg.Text(text='', key='decode_message', size=(40, 2))],
            [sg.Column([[sg.Button(button_text="Decode", key='data_decryption_button')]])]
        ], vertical_alignment='top')
    ]
]

#Defining tab 3
tab3_layout = [
    [
        sg.Column([
            [sg.Text("Key size")],
            [sg.Combo(('2048', '3072', '4096', '8192'), default_value='2048', key='key_size_combo')],
            [sg.Text("Output Folder")],
            [sg.Column([[sg.Input(key='keys_output_fol'), sg.FolderBrowse(key='keys_output_fol_browse')]], key='keys_output_fol_row')],
            [sg.Text(text='', key='keys_output_fol_message', size=(40, 2))],
            [sg.Button(button_text="Generate Keys", key='generate_button')]
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
                window['public_key_msg'].update("Public Key didn't Entered", text_color='red')

# Hiding message in image file
        if values['audio_checkbox']:
            if not os.path.exists(values['audio_file']):
                window['audio_msg'].update("Image File not Given", text_color='red')

        # Using RSA Encryption without using Steganography
        try:
            if values['rsa_radio']:

                if not values['audio_checkbox']:
                    if os.path.exists(values['output_fol']) and os.path.exists(values['public_key']):
                        window['output_fol_message'].update('')
                        window['public_key_msg'].update('')

                        # Encrypting text message using RSA encryption
                        if values['text_radio']:
                            with open(values['output_fol'] + '/encrypted', 'wb') as outputFile:
                                publicKey = crypto.ImportKey(values['public_key'])
                                outputFile.write(b'enct' + crypto.EncryptRSA(values['message'], publicKey))
                                window['secret_message_text'].update("Successfully Encrypted", text_color='green')


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
                                outputFile.write(b'encf' + bytes(fileExtLength, 'utf-8') + bytes(fileExt, 'utf-8') + crypto.EncryptRSA(str(file.hex()), publicKey))
                                window['secret_message_text'].update("Successfully Encrypted", text_color='green')

                # Using RSA Encryption with using Steganography
                elif values['audio_checkbox']:
                    if os.path.exists(values['output_fol']) and os.path.exists(values['public_key']) and os.path.exists(values['audio_file']):
                        window['output_fol_message'].update('')
                        window['public_key_msg'].update('')
                        window['audio_msg'].update('')

                        # Encrypting text message using RSA encryption & Hiding that message inside image file
                        if values['text_radio']:
                            publicKey = crypto.ImportKey(values['public_key'])
                            encrypted = 'enct' + str(bytes.hex(crypto.EncryptRSA(values['message'], publicKey)))
                            stego.AudioEncode(values['audio_file'], encrypted, values['output_fol'] + '/encoded_audio.wav')
                            window['secret_message_text'].update("Successfully Encoded", text_color='green')

                        # Encrypting file using RSA encryption & Hiding that message inside image file
                        elif values['file_radio']:
                            fileExt = str(values['file']).split('.')[-1].lower()
                            if fileExt.find('/') != -1:
                                fileExt = 'file'

                            file = open(values['file'], 'rb').read()
                            publicKey = crypto.ImportKey(values['public_key'])
                            encrypted = 'encf' + str(len(fileExt)) + fileExt + str(bytes.hex(crypto.EncryptRSA(str(file.hex()), publicKey)))
                            stego.AudioEncode(values['audio_file'], encrypted, values['output_fol'] + '/encoded_audio.wav')
                            window['secret_message_text'].update("Successfully encoded", text_color='green')

            # Using AES Encryption without using Steganography
            elif values['aes_radio']:

                if not values['audio_checkbox']:
                    if os.path.exists(values['output_fol']) and os.path.exists(values['public_key']):
                        window['output_fol_message'].update('')
                        window['public_key_msg'].update('')

                        # Encrypting text message using AES encryption
                        if values['text_radio']:
                            with open(values['output_fol'] + '/encrypted', 'wb') as outputFile:
                                crypto.EncryptAES(values['message'], values['public_key'], values['output_fol'] + '/encrypted', 'enc_text_aes')
                                window['secret_message_text'].update("Successfully encrypted", text_color='green')

                        # Encrypting text message using RSA encryption
                        elif values['file_radio']:
                            with open(values['output_fol'] + '/encrypted', 'wb') as outputFile:
                                fileExt = str(values['file']).split('.')[-1].lower()
                                if fileExt.find('/') != -1:
                                    fileExt = 'file'

                                file = open(values['file'], 'rb').read()
                                crypto.EncryptAES(bytes.hex(file), values['public_key'], values['output_fol'] + '/encrypted', 'enc_file_aes_' + fileExt)
                                window['secret_message_text'].update("Successfully encrypted", text_color='green')

                # Using AES Encryption with using Steganography
                elif values['audio_checkbox']:
                    if os.path.exists(values['output_fol']) and os.path.exists(values['public_key']) and os.path.exists(values['audio_file']):
                        window['output_fol_message'].update('')
                        window['public_key_msg'].update('')
                        window['audio_msg'].update('')

                        # Encrypting text message using AES encryption & Hiding that message inside image file
                        if values['text_radio']:
                            header, sessionKeyEncrypted, nonce, tag, ciphertext = crypto.EncryptAES(values['message'], values['public_key'], header='enc_text_aes')
                            stego.AudioEncode(values['audio_file'], bytes.hex(header) + bytes.hex(sessionKeyEncrypted) + bytes.hex(nonce) + bytes.hex(tag) + bytes.hex(ciphertext), values['output_fol'] + '/encoded_audio.wav')
                            window['secret_message_text'].update("Successfully Encoded", text_color='green')

                        # Encrypting file using AES encryption & Hiding that message inside image file
                        elif values['file_radio']:
                            fileExt = str(values['file']).split('.')[-1].lower()
                            if fileExt.find('/') != -1:
                                fileExt = 'file'

                            file = open(values['file'], 'rb').read()
                            header, sessionKeyEncrypted, nonce, tag, ciphertext = crypto.EncryptAES(bytes.hex(file), values['public_key'], header='enc_file_aes_' + fileExt)
                            stego.AudioEncode(values['audio_file'], bytes.hex(header) + bytes.hex(sessionKeyEncrypted) + bytes.hex(nonce) + bytes.hex(tag) + bytes.hex(ciphertext), values['output_fol'] + '/encoded_audio.wav')
                            window['secret_message_text'].update("Successfully Encoded", text_color='green')

            # Image Steganography without using encryption
            elif values['no_encryption_radio'] and values['audio_checkbox']:
                if os.path.exists(values['output_fol']) and os.path.exists(values['audio_file']):
                    window['output_fol_message'].update('')
                    window['audio_msg'].update('')

                    # Text message hide inside image
                    if values['text_radio']:
                        stego.AudioEncode(values['audio_file'], 'plnt' + values['message'], values['output_fol'] + '/encoded_audio.wav')
                        window['secret_message_text'].update("Successfully Encoded", text_color='green')

                    # File hide inside image
                    elif values['file_radio']:
                        fileExt = str(values['file']).split('.')[-1].lower()
                        if fileExt.find('/') != -1:
                            fileExt = 'file'

                        file = open(values['file'], 'rb').read()
                        stego.AudioEncode(values['audio_file'], 'plnf' + str(len(fileExt)) + fileExt + bytes.hex(file), values['output_fol'] + '/encoded_audio.wav')
                        window['secret_message_text'].update("Successfully Encoded", text_color='green')

        except Exception as exception:
            window['secret_message_text'].update("Unable to Encrypt\n" + str(exception), text_color='red')

    # Data Dencryption and Unhiding in Stego Media
    elif event == 'data_decryption_button':
        if not os.path.exists(values['encrypted_file']):
            window['encrypted_message_file'].update("Encrypted File didn't Selected", text_color='red')

        # Selecting private key
        try:
            if str(values['encrypted_file']).split('.')[-1].lower() != 'wav':
                if not os.path.exists(values['private_key']):
                    window['private_key_message'].update("Private Key didn't Entered", text_color='red')

                else:
                    privateKey = crypto.ImportKey(values['private_key'])
                    file = open(values['encrypted_file'], 'rb').read()

                    if str(file[0:4], 'utf-8') == 'enct':
                        decrypted = str(crypto.DecryptRSA(file[4:], privateKey), 'utf-8')
                        window['decrypted_message'].update(decrypted)
                        window['decode_message'].update("Successfully decrypted file", text_color='green')

                    elif str(file[0:4], 'utf-8') == '12en':
                        if str(file[0:14], 'utf-8') == '12enc_text_aes':
                            decrypted, header = crypto.DecryptAES(values['encrypted_file'], values['private_key'])
                            window['decrypted_message'].update(str(decrypted, 'utf-8'))
                            window['decode_message'].update("Successfully decrypted file", text_color='green')

                    elif not os.path.exists(values['decrypt_file_output_fol']):
                        window['decrypt_file_output_fol_message'].update("Output Folder not given", text_color='red')

                    elif str(file[0:4], 'utf-8') == 'encf':
                        fileExtLength = int(chr(file[4]) + chr(file[5]))
                        fileExt = str(file[6:(6 + fileExtLength)], 'utf-8')
                        decrypted = str(bytes.fromhex(str(crypto.DecryptRSA(file[(6 + fileExtLength):], privateKey), 'utf-8')), 'utf-8')
                        with open(values['decrypt_file_output_fol'] + '/decrypted.' + fileExt, 'wb') as outputFile:
                            outputFile.write(bytes(decrypted, 'utf-8'))

                        try:
                            window['decrypted_message'].update("Saved decrypted data to file. Contents:\n\n" + decrypted)

                        except Exception:
                            window['decrypted_message'].update("Saved decrypted data to file.")

                        window['decode_message'].update("Successfully decrypted file", text_color='green')

                    elif str(file[0:14], 'utf-8').find('enc_file_aes') != -1:
                        decrypted, header = crypto.DecryptAES(values['encrypted_file'], values['private_key'])
                        fileExt = header[15:]
                        with open(values['decrypt_file_output_fol'] + '/decrypted.' + fileExt, 'wb') as outputFile:
                            outputFile.write(bytes.fromhex(str(decrypted, 'utf-8')))

                        try:
                            window['decrypted_message'].update("Saved decrypted data to file. Contents:\n\n" + str(bytes.fromhex(str(decrypted, 'utf-8')), 'utf-8'))

                        except Exception:
                            window['decrypted_message'].update("Saved decrypted data to file.")

                        window['decode_message'].update("Successfully decrypted file", text_color='green')

                    else:
                        window['decrypted_message'].update('')
                        window['decode_message'].update("Unable to decrypt file\n" + "unknown file", text_color='red')

            elif str(values['encrypted_file']).split('.')[-1].lower() == 'wav':
                if os.path.exists(values['encrypted_file']):
                    window['encrypted_message_file'].update('')
                    window['private_key_message'].update('')
                    file = stego.AudioDecode(values['encrypted_file'])
                    try:
                        filefromhex = bytes.fromhex(file)

                    except Exception:
                        filefromhex = file

                    if file[0:4] == 'plnt':
                        window['decrypted_message'].update(file[4:])
                        window['decode_message'].update('Successfully decrypted file', text_color='green')

                    elif file[0:4] == 'plnf':
                        fileExtLength = int(file[4])
                        fileExt = file[5:(5 + fileExtLength)]
                        with open(values['decrypt_file_output_fol'] + '/decrypted.' + fileExt, 'wb') as outputFile:
                            outputFile.write(bytes.fromhex(file[(5 + fileExtLength):]))

                        try:
                            window['decrypted_message'].update("Saved decrypted data to file. Contents:\n\n" + str(bytes.fromhex(file[(5 + fileExtLength):]), 'utf-8'))

                        except Exception:
                            window['decrypted_message'].update("Saved decrypted data to file.")

                        window['decode_message'].update("Successfully decrypted file", text_color='green')

                    elif not os.path.exists(values['private_key']):
                        window['private_key_message'].update("Private Key didn't Entered", text_color='red')

                    elif os.path.exists(values['private_key']):
                        privateKey = crypto.ImportKey(values['private_key'])
                        if file[0:4] == 'enct':
                            decrypted = str(crypto.DecryptRSA(bytes.fromhex(file[4:]), privateKey), 'utf-8')
                            window['decrypted_message'].update(decrypted)
                            window['decode_message'].update("Successfully decrypted file", text_color='green')

                        elif not os.path.exists(values['decrypt_file_output_fol']):
                            window['decrypt_file_output_fol_message'].update("Output Folder not define", text_color='red')

                        elif type(filefromhex) == bytes:
                            if str(filefromhex[0:14], 'utf-8') == '12enc_text_aes':
                                with open(values['decrypt_file_output_fol'] + '/aes_text_fromhex_temp', 'wb') as tempFile:
                                    tempFile.write(filefromhex)

                                decrypted, header = crypto.DecryptAES(values['decrypt_file_output_fol'] + '/aes_text_fromhex_temp', values['private_key'])
                                os.remove(values['decrypt_file_output_fol'] + '/aes_text_fromhex_temp')
                                window['decrypted_message'].update(str(decrypted, 'utf-8'))
                                window['decode_message'].update("Successfully decrypted file", text_color='green')

                            elif str(filefromhex[0:14], 'utf-8').find('enc_file_aes') != -1:
                                with open(values['decrypt_file_output_fol'] + '/aes_file_fromhex_temp', 'wb') as tempFile:
                                    tempFile.write(filefromhex)

                                decrypted, header = crypto.DecryptAES(values['decrypt_file_output_fol'] + '/aes_file_fromhex_temp', values['private_key'])
                                fileExt = header[15:]
                                with open(values['decrypt_file_output_fol'] + '/decrypted.' + fileExt, 'wb') as outputFile:
                                    outputFile.write(bytes.fromhex(str(decrypted, 'utf-8')))

                                try:
                                    window['decrypted_message'].update("Saved decrypted data to file. Contents:\n\n" + str(bytes.fromhex(str(decrypted, 'utf-8')), 'utf-8'))

                                except Exception:
                                    window['decrypted_message'].update("Saved decrypted data to file.")

                                os.remove(values['decrypt_file_output_fol'] + '/aes_file_fromhex_temp')
                                window['decode_message'].update("Successfully decrypted file", text_color='green')

                        elif file[0:4] == 'encf':
                            fileExtLength = int(file[4] + file[5])
                            fileExt = file[6:(6 + fileExtLength)]
                            decrypted = str(bytes.fromhex(str(crypto.DecryptRSA(bytes.fromhex(file[(6 + fileExtLength):]), privateKey), 'utf-8')), 'utf-8')
                            with open(values['decrypt_file_output_fol'] + '/decrypted.' + fileExt, 'wb') as outputFile:
                                outputFile.write(bytes(decrypted, 'utf-8'))

                            try:
                                window['decrypted_message'].update("Saved decrypted data to file. Contents:\n\n" + decrypted)

                            except Exception:
                                window['decrypted_message'].update("Saved decrypted data to file.")

                            window['decode_message'].update("Successfully decrypted file", text_color='green')

                    else:
                        window['decrypted_message'].update('')
                        window['decode_message'].update("Unable to decrypt file\n" + "unknown file", text_color='red')

        except Exception as exception:
            window['decrypted_message'].update('')
            window['decode_message'].update("Unable to decrypt file\n" + str(exception), text_color='red')

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

    if values['no_encryption_radio']:
        window['audio_checkbox'].update(True, disabled=True)
        window['audio_file'].update(disabled=False)
        window['audio_browse'].update(disabled=False)
        window['public_key'].update(disabled=True)
        window['public_key_browse'].update(disabled=True)

    elif not values['no_encryption_radio']:
        window['audio_checkbox'].update(disabled=False)
        window['audio_file'].update(disabled=False)
        window['audio_browse'].update(disabled=False)
        window['public_key'].update(disabled=False)
        window['public_key_browse'].update(disabled=False)

    if values['audio_checkbox']:
        window['audio_file'].update(disabled=False)
        window['audio_browse'].update(disabled=False)

    elif not values['audio_checkbox'] and not values['no_encryption_radio']:
        window['audio_file'].update(disabled=True)
        window['audio_browse'].update(disabled=True)

window.close()
