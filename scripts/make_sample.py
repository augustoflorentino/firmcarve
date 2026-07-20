import gzip, io, os, random, struct, tarfile

def cpio(files):
    out = b""
    for i, (name, data) in enumerate(files + [("TRAILER!!!", b"")]):
        n = name.encode() + b"\0"
        mode = 0o100644 if data or name != "TRAILER!!!" else 0
        hdr = "070701" + "".join("%08x" % v for v in (i + 1, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(n), 0))
        out += hdr.encode() + n
        out += b"\0" * (-len(out) % 4) + data
        out += b"\0" * (-len(out) % 4)
    return out

def tar(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as t:
        for name, data in files:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()

rng = random.Random(7)
pem = b"-----BEGIN CERTIFICATE-----\n" + b"QUJD" * 40 + b"\n-----END CERTIFICATE-----\n"
inner = cpio([("etc/cert.pem", pem), ("etc/motd", b"hello\n" * 50)])
blob = b"\xff" * 4096 + gzip.compress(inner, mtime=0) + b"\0" * 512
blob += tar([("a/readme", b"firmcarve sample\n" * 20)])
blob += b"\0" * (-len(blob) % 4096) + bytes(rng.getrandbits(8) for _ in range(196608))
blob += b"tail-garbage-bytes-not-padding"
path = os.path.join(os.path.dirname(__file__), "..", "tests", "data", "sample.bin")
open(path, "wb").write(blob)
