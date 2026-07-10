import socket
import sys
import hashlib
import importlib.util
from pathlib import Path

_aes_spec = importlib.util.spec_from_file_location("_task1", Path("2105079_task1.py"))
assert _aes_spec is not None and _aes_spec.loader is not None, "Could not load 2105079_task1.py"
_task1_mod = importlib.util.module_from_spec(_aes_spec)
_aes_spec.loader.exec_module(_task1_mod)
AES = _task1_mod.AES


_dh_spec = importlib.util.spec_from_file_location("_task2", Path("2105079_task2.py"))
assert _dh_spec is not None and _dh_spec.loader is not None, "Could not load task2.py"
_task2_mod = importlib.util.module_from_spec(_dh_spec)
_dh_spec.loader.exec_module(_task2_mod)
DiffieHellman = _task2_mod.DiffieHellman


HOST = 'localhost'
PORT = 8000
AES_ROUNDS = 9         


def derive_key(shared_secret):
    return hashlib.sha256(str(shared_secret).encode()).digest()[:16]


def send_bytes(sock, data):
    sock.sendall(len(data).to_bytes(4, 'big'))
    sock.sendall(data)


def recv_bytes(sock):
    length = int.from_bytes(_recv_exact(sock, 4), 'big')
    return _recv_exact(sock, length)


def _recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed unexpectedly")
        buf += chunk
    return buf


def send_line(sock, text):
    sock.sendall((text + '\n').encode())


def recv_line(sock):
    data = b''
    while True:
        ch = sock.recv(1)
        if not ch:
            raise ConnectionError("Connection closed unexpectedly")
        if ch == b'\n':
            break
        data += ch
    return data.decode()



def run_alice():
    print("=" * 60)
    print("   ALICE  (sender)")
    print("=" * 60)

    print("\nGenerating parameters (P, g) and private key Ka ...")
    dh = DiffieHellman(key_size=128)
    Ka = dh.generate_private_key()
    A = dh.compute_public_key(Ka)

    print(f"  P  = {dh.P}")
    print(f"  g  = {dh.g}")
    print(f"  Ka = {Ka}")
    print(f"  A  = {A}")

    print(f"\n Listening on {HOST}:{PORT} for BOB ...")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    conn, addr = server.accept()
    print(f"BOB connected from {addr}")

    with conn:
        send_line(conn, str(dh.P))
        send_line(conn, str(dh.g))
        send_line(conn, str(A))
        print(" Sent P, g, A to BOB")

        B = int(recv_line(conn))
        print(f"Received B = {B}")

        shared = dh.compute_shared_secret(Ka, B)
        aes_key = derive_key(shared)
        print(f"Shared secret S = {shared}")
        print(f"AES-128 key      = {aes_key.hex()}")

        send_line(conn, "READY")
        print("Sent READY signal\n")

        while True:
            try:
                msg = input("Enter plaintext (or empty line to quit): ")
            except EOFError:
                break
            if msg == "":
                send_bytes(conn, b"")    
                print(" Quit signal sent.  Goodbye.")
                break

            aes = AES('ignored', mode='CBC', plaintext='ignored')
            aes.set_key_bytes(aes_key)
            aes.byte_text = bytearray(aes.padding(msg.encode('ascii')))
            enc_list = aes.CBC(AES_ROUNDS)

            ct = b''.join(bytes(b) for b in enc_list)

            send_bytes(conn, ct)
            print(f"Ciphertext (hex): {ct.hex()}")
            print(f"Ciphertext sent ({len(ct)} bytes)")

    server.close()
    print("ALICE finished.")



def run_bob():
    print("=" * 60)
    print("   BOB  (receiver)")
    print("=" * 60)

    print(f"\n Connecting to ALICE at {HOST}:{PORT} ...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print("Connected.")

    with sock:
        P = int(recv_line(sock))
        g = int(recv_line(sock))
        A = int(recv_line(sock))
        print(f"\nReceived from ALICE:")
        print(f"  P = {P}")
        print(f"  g = {g}")
        print(f"  A = {A}")

        dh = DiffieHellman(key_size=128)
        dh.set_params(P, g)
        Kb = dh.generate_private_key()
        B = dh.compute_public_key(Kb)
        print(f"\nBOB's keys:")
        print(f"  Kb = {Kb}")
        print(f"  B  = {B}")

        send_line(sock, str(B))
        print("Sent B to ALICE")

        shared = dh.compute_shared_secret(Kb, A)
        aes_key = derive_key(shared)
        print(f"Shared secret S = {shared}")
        print(f"AES-128 key      = {aes_key.hex()}")

        ready = recv_line(sock)
        if ready == "READY":
            print("Received READY — ALICE is ready to send.\n")
        else:
            print(f"Unexpected signal: {ready}")

        while True:
            ct = recv_bytes(sock)
            if ct == b"":                    
                print("ALICE closed the conversation.  Goodbye.")
                break

            print(f"Received ciphertext ({len(ct)} bytes)")
            print(f"Ciphertext (hex): {ct.hex()}")

            blocks = [bytearray(ct[i:i+16]) for i in range(0, len(ct), 16)]

            aes = AES('ignored', mode='CBC', plaintext='ignored')
            aes.set_key_bytes(aes_key)
            aes.cbc_encrypted_text = blocks
            pt = aes.CBC_decrypt(AES_ROUNDS)

            print(f"Decrypted plaintext: {pt.decode()}")

    print("BOB finished.")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1].lower() not in ("alice", "bob"):
        sys.exit(1)

    role = sys.argv[1].lower()
    if role == "alice":
        run_alice()
    else:
        run_bob()
