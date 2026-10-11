#!/usr/bin/env python3
"""TLS 1.3 handshake benchmark: ECDSA P-256 vs ML-DSA-44/65 certificates,
classical X25519 vs hybrid X25519MLKEM768 key exchange. Loopback, OpenSSL >= 3.5.
Usage: OPENSSL=/path/to/openssl [LD_LIBRARY_PATH=...] python3 mldsa_bench.py [N=200]"""
import os, subprocess, sys, time, resource, statistics as st, math, tempfile, socket, json

OSSL = os.environ.get("OPENSSL", "openssl")
N = int(sys.argv[1]) if len(sys.argv) > 1 else 200
WARM = 20
d = tempfile.mkdtemp(prefix="mldsa_")

def run(*a, **kw):
    return subprocess.run([OSSL, *a], check=True, capture_output=True, text=True, cwd=d, **kw)

def make_chain(name, alg_args):
    """Create CA + server certificate with the given key algorithm."""
    run("genpkey", *alg_args, "-out", f"{name}_ca.key")
    run("req", "-x509", "-new", "-key", f"{name}_ca.key", "-subj", f"/CN={name} test CA", "-days", "30", "-out", f"{name}_ca.crt")
    run("genpkey", *alg_args, "-out", f"{name}_srv.key")
    run("req", "-new", "-key", f"{name}_srv.key", "-subj", "/CN=localhost", "-out", f"{name}_srv.csr")
    ext = os.path.join(d, f"{name}.ext"); open(ext, "w").write("subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\n")
    run("x509", "-req", "-in", f"{name}_srv.csr", "-CA", f"{name}_ca.crt", "-CAkey", f"{name}_ca.key",
        "-CAcreateserial", "-days", "30", "-extfile", ext, "-out", f"{name}_srv.crt")

CERTS = {
    "ECDSA P-256": ("ec", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]),
    "ML-DSA-44":   ("mldsa44", ["-algorithm", "ML-DSA-44"]),
    "ML-DSA-65":   ("mldsa65", ["-algorithm", "ML-DSA-65"]),
}
for label, (n, a) in CERTS.items():
    make_chain(n, a)

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

def child_cpu():
    r = resource.getrusage(resource.RUSAGE_CHILDREN); return r.ru_utime + r.ru_stime

def ci95(x):
    return 1.96 * st.stdev(x) / math.sqrt(len(x)) if len(x) > 1 else 0.0

def bench(cert_label, group):
    n = CERTS[cert_label][0]; port = free_port()
    srv = subprocess.Popen([OSSL, "s_server", "-accept", str(port), "-cert", f"{n}_srv.crt", "-key", f"{n}_srv.key",
                            "-tls1_3", "-groups", group, "-www", "-quiet"], cwd=d,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.6)
    cmd = [OSSL, "s_client", "-connect", f"127.0.0.1:{port}", "-servername", "localhost", "-verify_hostname", "localhost",
           "-CAfile", f"{n}_ca.crt", "-tls1_3", "-groups", group, "-verify_return_error"]
    # one verbose check: negotiated group, signature, verification result, bytes
    chk = subprocess.run(cmd + ["-msg"], input="", capture_output=True, text=True, cwd=d)
    out = chk.stdout + chk.stderr
    ok = "Verify return code: 0 (ok)" in out
    grp = [l.split(":")[-1].strip() for l in out.splitlines() if "Negotiated TLS1.3 group" in l]
    if not grp: grp = [l.split(":")[-1].strip().split(",")[0] for l in out.splitlines() if "Peer Temp Key" in l]
    sig = [l.split(":")[-1].strip() for l in out.splitlines() if l.strip().startswith("Peer signature type")]
    der = subprocess.run([OSSL, "x509", "-in", f"{n}_srv.crt", "-outform", "DER"], capture_output=True, cwd=d).stdout
    cert_bytes = len(der)  # DER size of the server certificate (CA certificate is not sent)
    for _ in range(WARM): subprocess.run(cmd, input="", capture_output=True, text=True, cwd=d)
    times, c0 = [], child_cpu()
    for _ in range(N):
        t = time.perf_counter(); r = subprocess.run(cmd, input="", capture_output=True, text=True, cwd=d)
        times.append((time.perf_counter() - t) * 1e3)
    cpu = (child_cpu() - c0) / N * 1e3  # client process only
    srv.terminate(); srv.wait()
    return dict(cert=cert_label, group=group, ok=ok, negotiated=grp[0] if grp else "?", sig=sig[0] if sig else "?",
                n=N, mean_ms=st.mean(times), ci=ci95(times), cpu_client_ms=cpu, cert_msg_bytes=cert_bytes)

# empty invocation cost
e = []
for _ in range(N):
    t = time.perf_counter(); subprocess.run([OSSL, "version"], capture_output=True, cwd=d); e.append((time.perf_counter() - t) * 1e3)
empty = st.mean(e)

res = []
for c in CERTS:
    for g in ("X25519", "X25519MLKEM768"):
        res.append(bench(c, g))

print(f"# {subprocess.run([OSSL,'version'],capture_output=True,text=True).stdout.strip()} | N={N} | empty openssl invocation {empty:.2f} ms")
print(f"{'certificate':12} {'group':16} {'verify':6} {'negotiated':16} {'signature':14} {'handshake ms (mean ± 95% CI)':30} {'client CPU ms':>13} {'Srv cert B':>10}")
for r in res:
    print(f"{r['cert']:12} {r['group']:16} {'ok' if r['ok'] else 'FAIL':6} {r['negotiated']:16} {r['sig']:14} {r['mean_ms']:8.2f} ± {r['ci']:5.2f}{'':14} {r['cpu_client_ms']:13.2f} {str(r['cert_msg_bytes']):>10}")
json.dump(res, open(os.path.join(d, "results.json"), "w"), indent=1)
print("raw results:", os.path.join(d, "results.json"))
