"""
Table 1: The parameter selection of our fs-IBE.
Reference: A lattice-based forward secure IBE scheme for Internet of things.
"""
from lattice_infrastructure import LatticeParams

# Table 1: Parameter sets with n, q, δ (approx), NIST level, bits security
FS_IBE_TABLE = [
    {
        "parameter": "PARA.512",
        "n": 512,
        "q": 3329,
        "delta_approx": "2^(-139)",
        "nist_level": 1,
        "bits_security": 143,
    },
    {
        "parameter": "PARA.768",
        "n": 768,
        "q": 3329,
        "delta_approx": "2^(-164)",
        "nist_level": 3,
        "bits_security": 207,
    },
    {
        "parameter": "PARA.1024",
        "n": 1024,
        "q": 3329,
        "delta_approx": "2^(-174)",
        "nist_level": 5,
        "bits_security": 272,
    },
]


def get_lattice_params(parameter_name):
    """Return LatticeParams for a Table 1 parameter set (e.g. 'PARA.512')."""
    for row in FS_IBE_TABLE:
        if row["parameter"] == parameter_name:
            return LatticeParams(n=row["n"], q=row["q"])
    raise KeyError(f"Unknown parameter: {parameter_name}")


def print_table_1():
    """Print Table 1: The parameter selection of our fs-IBE."""
    header = f"{'Parameter':<12} {'n':<8} {'q':<8} {'δ (approx)':<14} {'NIST Security (level)':<24} {'bits security':<16}"
    sep = "-" * 90
    lines = ["Table 1  The parameter selection of our fs-IBE.", "", header, sep]
    for row in FS_IBE_TABLE:
        lines.append(
            f"{row['parameter']:<12} {row['n']:<8} {row['q']:<8} {row['delta_approx']:<14} {row['nist_level']:<24} {row['bits_security']:<16}"
        )
    text = "\n".join(lines)
    print(text, flush=True)
    return text
