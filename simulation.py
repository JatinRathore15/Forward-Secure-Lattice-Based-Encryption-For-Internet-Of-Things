"""
P4: Full system simulation and benchmarking.
Outputs match the Word document and README:
- Data encryption time, Query encryption time, Data decryption time
- Query execution latency, Query throughput, Overall model throughput, Overall model latency
- False trust acceptance rate (FTAR)
- Results_Report.csv
"""
import sys
import time
import csv

# Ensure LatticeCrypto is available before importing P2/P3
import lattice_infrastructure
sys.modules["LatticeCrypto"] = lattice_infrastructure

import lattice_infrastructure as P1
from forward_security import UserOps
from Trust_Model import TrustManager, DilithiumStub, Query, QueryValidator


def run_simulation(n=64, num_data=5, num_queries=10, num_malicious=5, tree_depth=3, param_name=None):
    """
    Run full workflow: Setup -> Encrypt data -> Queries (Sign, CheckTrust, Match, Decrypt).
    Returns dict of metrics for output/CSV. If param_name is set, adds parameter info to metrics.
    """
    params = P1.LatticeParams(n=n)
    system = P1.Setup(tree_depth=tree_depth, params=params)
    ops = UserOps(system)
    tm = TrustManager()
    sig = DilithiumStub()
    sk_user, pk_user = b"user_sk", sig.pk_from_sk(b"user_sk")
    validator = QueryValidator(tm, sig, params)

    user_id = "Alice"
    epoch = 1
    nodes = list(range(min(epoch + 2, 2 ** tree_depth)))
    keys = ops.simulate_key_evolution(user_id, nodes)

    # ---- Data encryption (IoT stream) ----
    t0 = time.perf_counter()
    encrypted_data = []
    for i in range(num_data):
        bit = i % 2
        ct = ops.Encrypt(user_id, epoch, bit)
        encrypted_data.append(ct)
    data_encryption_time = time.perf_counter() - t0

    # ---- Query encryption time (T_Enc^Q) ----
    t_enc_q_list = []
    for _ in range(num_queries):
        t0 = time.perf_counter()
        ops.Encrypt(user_id, epoch, 1)
        t_enc_q_list.append(time.perf_counter() - t0)
    query_encryption_time = sum(t_enc_q_list) / len(t_enc_q_list) if t_enc_q_list else 0

    # ---- Trust verification time (T_Trust) ----
    def one_query():
        q = Query(b"keyword", b"", epoch)
        msg = b"P3|" + P1.G_vector(user_id, params).tobytes() + q.encrypted_keyword + q.epoch.to_bytes(8, "big")
        q.signature = sig.sign(msg, sk_user)
        return q, msg

    t_trust_list = []
    for _ in range(num_queries):
        q, msg = one_query()
        t0 = time.perf_counter()
        validator.validate(user_id, q, pk_user)
        t_trust_list.append(time.perf_counter() - t0)
    trust_time = sum(t_trust_list) / len(t_trust_list) if t_trust_list else 0

    # ---- Match (simulate: compare epoch/keyword) ----
    t_match_list = []
    for _ in range(num_queries):
        t0 = time.perf_counter()
        for ct in encrypted_data:
            if ct["epoch"] == epoch:
                break
        t_match_list.append(time.perf_counter() - t0)
    match_time = sum(t_match_list) / len(t_match_list) if t_match_list else 0

    # ---- Data decryption time ----
    t0 = time.perf_counter()
    for ct in encrypted_data:
        ops.Decrypt(ct, keys)
    data_decryption_time = time.perf_counter() - t0

    # ---- Decryption time per query (T_Dec) ----
    t_dec_list = []
    for _ in range(num_queries):
        ct = encrypted_data[0]
        t0 = time.perf_counter()
        ops.Decrypt(ct, keys)
        t_dec_list.append(time.perf_counter() - t0)
    query_decryption_time = sum(t_dec_list) / len(t_dec_list) if t_dec_list else 0

    # Query execution latency: T_Query = T_Enc^Q + T_Trust + T_Match + T_Dec
    t_query = query_encryption_time + trust_time + match_time + query_decryption_time

    # ---- Throughput: queries per second ----
    total_query_time = t_query * num_queries
    query_throughput = num_queries / total_query_time if total_query_time > 0 else 0

    # ---- Overall model: total time for (data enc + all queries + decryption) ----
    overall_latency = data_encryption_time + total_query_time + data_decryption_time
    total_ops = num_data + num_queries
    overall_throughput = total_ops / overall_latency if overall_latency > 0 else 0

    # ---- False Trust Acceptance Rate: malicious queries (bad signature) accepted ----
    malicious_accepted = 0
    for _ in range(num_malicious):
        q, msg = one_query()
        q.signature = b"wrong_signature"
        if validator.validate(user_id, q, pk_user):
            malicious_accepted += 1
    ftar = malicious_accepted / num_malicious if num_malicious > 0 else 0

    out = {
        "data_encryption_time_s": data_encryption_time,
        "query_encryption_time_s": query_encryption_time,
        "data_decryption_time_s": data_decryption_time,
        "query_execution_latency_s": t_query,
        "query_throughput_per_s": query_throughput,
        "overall_model_throughput_per_s": overall_throughput,
        "overall_model_latency_s": overall_latency,
        "false_trust_acceptance_rate": ftar,
        "num_data": num_data,
        "num_queries": num_queries,
        "num_malicious": num_malicious,
        "malicious_accepted": malicious_accepted,
    }
    if param_name is not None:
        out["parameter"] = param_name
        out["n"] = n
    return out


def print_results(metrics, param_name=None):
    """Print results table as per Word document and README. If param_name given, show parameter header."""
    if param_name:
        print("\n" + "=" * 60, flush=True)
        print(f"  Parameter: {param_name}  (n = {metrics.get('n', '—')})", flush=True)
        print("=" * 60, flush=True)
    else:
        print("\n" + "=" * 60, flush=True)
        print("  Results (as per Word document & README)", flush=True)
        print("=" * 60, flush=True)
    print(f"  Data encryption time          : {metrics['data_encryption_time_s']:.6f} s", flush=True)
    print(f"  Query encryption time         : {metrics['query_encryption_time_s']:.6f} s", flush=True)
    print(f"  Data decryption time          : {metrics['data_decryption_time_s']:.6f} s", flush=True)
    print(f"  Query execution latency       : {metrics['query_execution_latency_s']:.6f} s  (T_Enc^Q + T_Trust + T_Match + T_Dec)", flush=True)
    print(f"  Query throughput              : {metrics['query_throughput_per_s']:.2f} queries/s", flush=True)
    print(f"  Overall model throughput      : {metrics['overall_model_throughput_per_s']:.2f} ops/s", flush=True)
    print(f"  Overall model latency         : {metrics['overall_model_latency_s']:.6f} s", flush=True)
    print(f"  False trust acceptance rate   : {metrics['false_trust_acceptance_rate']:.2%}  ({metrics['malicious_accepted']}/{metrics['num_malicious']} malicious accepted)", flush=True)
    print("=" * 60, flush=True)


def run_all_three_parameters(num_data=5, num_queries=10, num_malicious=5, tree_depth=3):
    """Run simulation for PARA.512, PARA.768, PARA.1024. Returns list of (param_name, metrics)."""
    import fs_ibe_params
    all_metrics = []
    for row in fs_ibe_params.FS_IBE_TABLE:
        param_name = row["parameter"]
        n = row["n"]
        print(f"\n  Running simulation for {param_name} (n={n}) ...", flush=True)
        m = run_simulation(n=n, num_data=num_data, num_queries=num_queries, num_malicious=num_malicious, tree_depth=tree_depth, param_name=param_name)
        m["bits_security"] = row["bits_security"]
        m["nist_level"] = row["nist_level"]
        all_metrics.append(m)
    return all_metrics


def print_results_all_three(all_metrics):
    """Print results for each of the 3 parameters separately."""
    for m in all_metrics:
        print_results(m, param_name=m["parameter"])


def save_csv_all_three(all_metrics, path="Results_Report.csv"):
    """Save one row per parameter (PARA.512, PARA.768, PARA.1024) to CSV."""
    if not all_metrics:
        return
    keys = ["parameter", "n", "bits_security", "nist_level"] + [k for k in all_metrics[0].keys() if k not in ("parameter", "n", "bits_security", "nist_level")]
    # ensure column order
    row0 = all_metrics[0]
    fieldnames = ["parameter", "n", "bits_security", "nist_level", "data_encryption_time_s", "query_encryption_time_s", "data_decryption_time_s", "query_execution_latency_s", "query_throughput_per_s", "overall_model_throughput_per_s", "overall_model_latency_s", "false_trust_acceptance_rate", "num_data", "num_queries", "num_malicious", "malicious_accepted"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        for m in all_metrics:
            w.writerow(m)
    print(f"\n  Saved: {path}  (3 rows: PARA.512, PARA.768, PARA.1024)", flush=True)


def save_csv(metrics, path="Results_Report.csv"):
    """Save execution times and metrics to CSV (README P4 deliverable)."""
    row = {
        "data_encryption_time_s": metrics["data_encryption_time_s"],
        "query_encryption_time_s": metrics["query_encryption_time_s"],
        "data_decryption_time_s": metrics["data_decryption_time_s"],
        "query_execution_latency_s": metrics["query_execution_latency_s"],
        "query_throughput_per_s": metrics["query_throughput_per_s"],
        "overall_model_throughput_per_s": metrics["overall_model_throughput_per_s"],
        "overall_model_latency_s": metrics["overall_model_latency_s"],
        "false_trust_acceptance_rate": metrics["false_trust_acceptance_rate"],
        "num_data": metrics["num_data"],
        "num_queries": metrics["num_queries"],
        "num_malicious": metrics["num_malicious"],
        "malicious_accepted": metrics["malicious_accepted"],
    }
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(row.keys()))
        w.writeheader()
        w.writerow(row)
    print(f"  Saved: {path}", flush=True)


if __name__ == "__main__":
    print("Running simulation for all 3 parameters (PARA.512, PARA.768, PARA.1024)...", flush=True)
    all_metrics = run_all_three_parameters(num_data=5, num_queries=10, num_malicious=5)
    print_results_all_three(all_metrics)
    save_csv_all_three(all_metrics, path="Results_Report.csv")
