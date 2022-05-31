import wave
def AudioEncode(path, message):
    end_char = '#$%' # denotes message end
    # song = wave.open('song.wav', 'rb')
    song = wave.open(path, 'rb')
    # f = open('message.txt' , 'r+')
    # msg_list = f.read().split()
    # # f.close()
    # message = ''
    # for i in msg_list:
    #     message= message + i + ' '
    print(message)

    '''
        This will give us the number of bytes of frames that we have
        song.getnframes() -> gets the number of audio frames
        song.readframes() -> read those frames and return a binary string 
        bytearray-> converts the normal list to bytearray
    '''
    frame_byte = bytearray(list(song.readframes(song.getnframes())))
    # print(frame_byte[1002310])
    # print(len(frames))

    '''
        len(message)-> number of bytes required
        *8 -> will give us the number of bits that we need
        each framebyte can only store 1 bit of data(LSB)
        Therefore, we will require that many frame_bytes as the number of bits that we need. Others are extra
    '''
    # message = message + min(int((len(frame_byte) - len(message)*8)/8), 3)*'#'
    if(len(frame_byte) - len(message)*8 - len(end_char)*8< 0): # 24 for ending characters
        print('Reduce the message size')

    # add end of message
    message += end_char

    print(message)

    #char->ascii(int)->binaryRepresentation->remove 0b prefix
    x = [bin(ord(i)).lstrip('0b') for i in message]
    #make it in the form of 8bits i.e 1 byte. Eg: 5: 101 -> 00000101
    y = [i.rjust(8, '0') for i in x]
    #convert to string
    tempStr = ''.join(y)
    #convert char to int : '1': 1, '0': 0
    bitArray = list(map(int, tempStr))
    for i, bit in enumerate(bitArray):
        #Add the required bit to the LSB of the frame byte
        frame_byte[i] = (frame_byte[i]&254) | bit
    #convert the message to a string of bytes
    frame_modified = bytes(frame_byte)

    #save the song
    with wave.open('song_embedded.wav', 'wb') as fd:
        fd.setparams(song.getparams())
        fd.writeframes(frame_modified)
    song.close()

def AudioDecode(path):

        end_char = '#$%'

        # song = wave.open('song_embedded.wav', 'rb')
        song = wave.open(path, 'rb')

        frame_bytes = bytearray(list(song.readframes(song.getnframes())))

        received = [frame_bytes[i] & 1 for i in range(len(frame_bytes))]
        # print(type(received[0]))

        decoded = ""
        for i in range(0, len(received), 8):
            '''
                map(str, [int list]): will convert all ints to string: [1,0,1]: ['1','0','1']
                .join(): convert list to string
                int(string, 2): convert given string to integer and the given base is 2(binary)
                chr: convert the given integer to it's corresponding character
            '''
            char = chr(int("".join(map(str, received[i:i + 8])), 2))
            decoded += char
            if end_char in decoded[len(decoded) - len(end_char) - 1:-1]:
                decoded = decoded.split(end_char)[0]
                break

        return decoded