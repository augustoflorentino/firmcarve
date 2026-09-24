import gzip, io, os, random, struct, subprocess, tarfile, zipfile, zlib

def cpio(files, links=()):
    out = b""
    entries = [(n, d, 0o100644) for n, d in files] + [(n, t.encode(), 0o120777) for n, t in links]
    for i, (name, data, mode) in enumerate(entries + [("TRAILER!!!", b"", 0)]):
        n = name.encode() + b"\0"
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

def zipped(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data, method in files:
            info = zipfile.ZipInfo(name, (2026, 7, 4, 0, 0, 0))
            info.compress_type = method
            z.writestr(info, data)
    return buf.getvalue()

def lzop(data):
    head = struct.pack(">HHHBBIIIIB", 0x1030, 0x2080, 0x0940, 1, 5, 0, 0o100644, 0, 0, 0)
    out = b"\x89LZO\0\r\n\x1a\n" + head + struct.pack(">I", zlib.adler32(head))
    return out + struct.pack(">II", len(data), len(data)) + data + b"\0\0\0\0"

def lz4(data):
    return subprocess.run(["lz4", "-c", "-9"], input=data, stdout=subprocess.PIPE, check=True).stdout

rng = random.Random(7)
pem = b"-----BEGIN CERTIFICATE-----\n" + b"QUJD" * 40 + b"\n-----END CERTIFICATE-----\n"
inner = cpio([("etc/cert.pem", pem), ("etc/motd", b"hello\n" * 50)])
blob = b"\xff" * 4096 + gzip.compress(inner, mtime=0) + b"\0" * 512
blob += tar([("a/readme", b"firmcarve sample\n" * 20)])
blob += b"\0" * 64 + zipped([("cfg/app.conf", b"key=value\n" * 40, zipfile.ZIP_DEFLATED),
                             ("cfg/raw.txt", b"stored entry\n", zipfile.ZIP_STORED)])
blob += b"\0" * 64 + lz4(pem * 3) + b"\0" * 64 + lzop(b"lzop stored block\n" * 8)
blob += b"\0" * (-len(blob) % 4096) + bytes(rng.getrandbits(8) for _ in range(196608))
blob += b"tail-garbage-bytes-not-padding"
data = os.path.join(os.path.dirname(__file__), "..", "tests", "data")
open(os.path.join(data, "sample.bin"), "wb").write(blob)
evil = cpio([("../../evil.txt", b"up"), ("/abs/file", b"abs"), ("dir\\back.txt", b"bs"), ("CON.txt", b"con"),
             ("a", b"lower"), ("A", b"upper"), ("sub/x", b"x")],
            [("out", "../../../../etc/passwd"), ("root", "/abs/file"), ("sub/chain", "../root"), ("sub/self", ".")])
open(os.path.join(data, "evil.bin"), "wb").write(evil)
