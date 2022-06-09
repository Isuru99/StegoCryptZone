import wave
def AudioEncode(path, message, output):
    end_char = '#$%' # denotes message end

    song = wave.open(path, 'rb')

    print(message)

    frame_byte = bytearray(list(song.readframes(song.getnframes())))
    print(frame_byte, "\n\n\n")



    # message = message + min(int((len(frame_byte) - len(message)*8)/8), 3)*'#'
    if(len(frame_byte) - len(message)*8 - len(end_char)*8< 0): # 24 for ending characters
        print('Reduce the message size')

    # add end of message
    message += end_char

    print(message)

  #char->ASCII(int)->binaryRepresentation->remove 0b prefix
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
    with wave.open(output, 'wb') as fd:
        fd.setparams(song.getparams())
        fd.writeframes(frame_modified)
    song.close()

def AudioDecode(audioPath):

        end_char = '#$%'

        song = wave.open(audioPath, 'rb')

        frame_bytes = bytearray(list(song.readframes(song.getnframes())))

        received = [frame_bytes[i] & 1 for i in range(len(frame_bytes))]

        decoded = ''
        for i in range(0, len(received), 8):

            char = chr(int("".join(map(str, received[i:i + 8])), 2))
            decoded += char
            if end_char in decoded[len(decoded) - len(end_char) - 1:-1]:
                decoded = decoded.split(end_char)[0]
                break

        return decoded

