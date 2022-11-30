def compress(pubKey):
    return (hex(pubKey.x) + hex(pubKey.y % 2)[2:])[2:34]