import PySimpleGUI as sg

sg.theme('Black')

tab1_layout = [
    [
        sg.Column([
            [sg.Radio("Encrypt with AES encryption", group_id='aes_rsa_radios', key='aes_radio', default=True, enable_events=True)],
            [sg.Radio("Encrypt with RSA encryption", group_id='aes_rsa_radios', key='rsa_radio', default=False, enable_events=True)],
            [sg.Radio("Do not encrypt", group_id='aes_rsa_radios', key='no_encryption_radio', default=False, enable_events=True)],
            [sg.Checkbox("Hide data inside image", key='image_checkbox', default=True, enable_events=True)],

            [sg.Text(text="Output folder", key='output_dir_title')],
            [sg.Column([[sg.Input(key='output_dir'), sg.FolderBrowse(key='output_dir_browse')]], key='output_dir_row')],
            [sg.Text(text='', key='output_dir_message', size=(40, 2))],

            [sg.Text(text="Public key", key='public_key_title')],
            [sg.Column([[sg.Input(key='public_key', disabled_readonly_background_color='black'), sg.FileBrowse(key='public_key_browse', file_types=(('PEM Files', '*.pem'), ))]], key='public_key_row')],
            [sg.Text(text='', key='public_key_message', size=(40, 2))],

            [sg.Radio("Image Steganography", group_id='stego_methods_radios', key='image_radio', default=True, enable_events=True)],
            [sg.Radio("Text Steganography", group_id='stego_methods_radios', key='text_radio', default=False, enable_events=True)],

            [sg.Text(text="File", key='image_file_title')],
            [sg.Column([[sg.Input(key='image_file', disabled_readonly_background_color='black'), sg.FileBrowse(key='image_file_browse', file_types=(('PNG Files', '*.png'), ))]], key='image_file_row')],
            [sg.Text(text='', key='image_file_message', size=(40, 2))]
        ])
    ]
]

layout = [
    [
        sg.TabGroup([
            [sg.Tab("Encrypt", tab1_layout)]
        ])
    ]
]

window = sg.Window("SteganoCryptZone", layout)
while True:
    window.refresh()
    event, values = window.read()
    if event == sg.WIN_CLOSED:
        break

window.close()