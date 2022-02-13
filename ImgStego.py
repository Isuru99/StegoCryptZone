from PIL import Image


def gData(data):

    nData = []
        for a in data:
            nData.append(format (ord(a), '08b'))

        return nData

def modiPixel(pix, data):
    datalist = gData(data)
    lendata = len(datalist)
    imdata = iter(pix)

    for a in range(lendata):

        pix = [value for value in imdata.__next__()[:3] + imdata.__next__()[:3] + imdata.__next__()[:3]]
        for b in range(0, 8):
            if (datalist[a][b] == '0' and pix[b] % 2 != 0):
                pix[b] -= 1

            elif (datalist[a][b] == '0' and pix[j] % 2 == 0):
                if(pix[b] != 0):
                    pix[b] -= 1

                else:
                    pix[b] += 1

def encode(imgPath, data, output):
    img = Image.open(imgPath, 'r')
    nImg = img.copy()
    encode_enc(nImg, data)
    nImg.save(output, 'PNG')
    nImg.save(output, 'JPEG')

def decode(imgPath):
    img = Image.open(imgPath, 'r')
    data = ''
    imgdata = iter(img.getdata())

    while (True):
        pixles = []








