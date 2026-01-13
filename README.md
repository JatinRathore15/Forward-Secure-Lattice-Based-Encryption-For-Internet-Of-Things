# Project: Lattice-Based Forward Secure IBE with Trust-Based Verification

## 1. Project Overview
**Objective:** Implement a secure IoT data sharing scheme using Lattice-Based Forward-Secure Identity-Based Encryption (fs-IBE). The system is enhanced with a novel **Trust Verification Model** using Post-Quantum Digital Signatures (Dilithium-3) to authenticate queries before execution.

**Core Reference Paper:** *A lattice-based forward secure IBE scheme for Internet of things* (Elsevier, Information Sciences).
**Modification Reference:** *Novel Approach: Secure query-based trust model*.

---

## 2. Architecture & Workflow
The system follows a pipeline where IoT data is encrypted using fs-IBE, and user queries are gated by a Trust Score system before decryption is allowed.

**Workflow:**
1.  **Data Collection:** IoT devices generate data.
2.  **Encryption:** Data is encrypted using **fs-IBE** (Lattice-based).
3.  **Query Generation:** User creates an encrypted query and **signs it** using Dilithium-3.
4.  **Trust Verification:** System checks the user's Trust Score.
    * `If Score < 0`: **Reject Query**.
    * `If Score >= 0`: Proceed to Query Execution.
5.  **Execution:** System matches the encrypted query with encrypted data.
6.  **Decryption:** If a match is found, the user receives the data and decrypts it using their secret key ($sk_{id, t}$).

---

## 3. Team Roles & Task Division

### 🧑‍💻 P1: Lattice Infrastructure & Key Generation (The "Root" Layer)
**Responsibility:** Implement the mathematical primitives (Lattice/LWE) and the Master Key setup. You provide the foundation for P2.

**Key Tasks:**
* [ ] **Lattice Primitives:**
    * Implement **`TrapGen(n, q)`**: Generates matrix $A \in \mathbb{Z}_q^{n \times m}$ and trapdoor $T_A$.
    * Implement **`SamplePre(A, T_A, u, sigma)`**: Gaussian sampling algorithm (inverse of function $f_A$) to sample short vectors.
* **Binary Tree Structure:**
    * Implement a `BinaryTree` class representing time epochs.
    * Implement Hash functions:
        * $H: \{0,1\}^* \to \mathbb{Z}_q^{n \times m}$ (Maps IDs/Nodes to matrices).
        * $G: \{0,1\}^* \to \mathbb{Z}_q^n$ (Maps IDs to vectors).
* **Setup Algorithms:**
    * **`Setup(N)`**: Output public parameters `params` and master secret key `msk`.
    * **`KeyGen(params, id, msk)`**: Generate the initial secret key $sk_{id, 0}$ for the user.

**Deliverable:** `LatticeCrypto.py` (or .cpp) containing the `TrapGen`, `SamplePre`, and `BinaryTree` classes.

---

### 🧑‍💻 P2: Forward Security & Cryptographic Operations (The "Time" Layer)
**Responsibility:** Implement the encryption/decryption logic and the *Forward Secure Update* mechanism that evolves keys over time.

**Key Tasks:**
* [ ] **Minimal Cover Mechanism:**
    * Implement **`MinCov(node)`**: A function that returns the minimal set of tree nodes required to cover the remaining time epochs.
* [ ] **Key Update (Forward Secrecy):**
    * Implement **`Update(params, sk_{id, t}, t)`**:
        * Input: Current key $sk_{id, t}$ at time $t$.
        * Logic: Compute $sk_{id, t+1}$ using `SamplePre` and the Binary Tree structure.
        * **Crucial:** Delete the old key $sk_{id, t}$ to ensure forward security.
* [ ] **Cryptographic Operations:**
    * **`Encrypt(params, id, t, message)`**: Implement Dual Regev encryption logic. Output ciphertext $(p, c)$.
    * **`Decrypt(params, C, sk_{id, t})`**: Recover message $M$ using the error vector from the secret key.

**Deliverable:** `UserOps.py` containing `Update`, `Encrypt`, and `Decrypt` functions.

---

### 🧑‍💻 P3: Trust Model & Novel Query Logic (The "Verification" Layer)
**Responsibility:** Implement the "Novel Approach" improvements: Dilithium signatures and the Trust Scoring logic.

**Key Tasks:**
* [ ] **Post-Quantum Signatures:**
    * Integrate **Dilithium-3** (NIST Security Level 3).
    * Implement `Sign(message, user_priv_key)` and `Verify(message, signature, user_pub_key)`.
* [ ] **Trust Model Logic:**
    * Create a `TrustDatabase` (Key-Value store: `UserID -> Score`).
    * Implement **`CheckTrust(UserID)`**: Returns `True` if Score $\ge 0$, else `False`.
    * Implement logic to decrease score on malicious attempts (e.g., bad signature).
* [ ] **Query Object Construction:**
    * Define the Query structure: `Q = { EncryptedKeyword, Signature, Epoch_ID }`.
    * Implement the **Match Logic**: Compare User Query vs. Stored Data tags.

**Deliverable:** `TrustModule.py` containing Dilithium wrapper and `TrustManager` class.

---

### 🧑‍💻 P4: Integration, Simulation & Benchmarking (The "Analyst" Layer)
**Responsibility:** Combine modules P1-P3, run the full simulation, and calculate the performance metrics required by the Word document.

**Key Tasks:**
* [ ] **System Integration (The Main Loop):**
    1.  Call P1 `Setup`.
    2.  Call P2 `Encrypt` (simulate IoT data stream).
    3.  Call P3 `Sign` (simulate User Query).
    4.  Call P3 `CheckTrust` (Gatekeeper).
    5.  Call P2 `Update` (Simulate time passing).
    6.  Call P2 `Decrypt` (If trust passes).
* [ ] **Performance Metrics (Formulas):**
    * Calculate **Query Latency ($T_{Query}$)**:
        $$T_{Query} = T_{Enc}^Q + T_{Trust} + T_{Match} + T_{Dec}$$
    * Calculate **Throughput**:
        $$Throughput_Q = \frac{\#Queries \ processed}{Time}$$
    * Calculate **False Trust Acceptance Rate (FTAR)**:
        $$FTAR = \frac{\#Malicious \ Queries \ Accepted}{\#Malicious \ Queries}$$
* [ ] **Reporting:**
    * Generate a log file or CSV with execution times for Encryption, Decryption, and Trust Verification.

**Deliverable:** `Main.py` (Simulation script) and the final `Results_Report.csv`.

---

## 4. Implementation Formulas (For Reference)

**1. Lattice Hardness (LWE):**
Given $(A, A^T s + e)$, distinguish from random uniform $(A, b)$. The security relies on the hardness of finding $s$.

**2. Query Time Calculation:**
The total time for a query is the sum of:
* $T_{Enc}^Q$: Time to encrypt the query keyword.
* $T_{Trust}$: Time to verify Dilithium signature + check Trust Score.
* $T_{Match}$: Time to search/match the keyword in the database.
* $T_{Dec}$: Time to decrypt the result.

**3. Binary Tree Depth:**
For $N$ time epochs, the tree depth is $l \approx \log N$. The parameters size depends logarithmically on $N$.

---

## 5. Development Roadmap

| Phase | Activity | Responsible |
| :--- | :--- | :--- |
| **Phase 1** | Implement `TrapGen`, `SamplePre`, & Tree Structure | **P1** |
| | Implement Basic `Encrypt` / `Decrypt` (Static Time) | **P2** |
| | Dilithium-3 Setup & Basic Trust Class | **P3** |
| **Phase 2** | Implement `Update` (Key Evolution) & MinCov | **P2** |
| | Implement `Sign` & `Verify` integration with Queries | **P3** |
| | Create Test Data Generator | **P4** |
| **Phase 3** | **Full Integration:** Connect P1 -> P2 -> P3 | **P4** (All assist) |
| **Phase 4** | Run Benchmarks (Throughput, FTAR, Latency) | **P4** |
