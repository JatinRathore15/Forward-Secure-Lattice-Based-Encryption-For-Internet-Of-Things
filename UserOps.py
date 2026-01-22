# ============================================
# UserOps.py
# P2: Forward Security & Cryptographic Ops
# ============================================

import numpy as np
import LatticeCrypto as P1  # Import P1's Lattice Infrastructure

class UserOps:
    """
    Handles Forward Secure operations and Cryptographic functions.
    This class manages the user's key lifecycle (evolution) and 
    performs Dual Regev encryption/decryption.
    """

    def __init__(self, system_setup):
        """
        Initialize with system parameters provided by P1 (LatticeCrypto).
        
        Args:
            system_setup (dict): Output from P1.Setup(), containing 'params', 'A', 'T_A', 'tree'.
        """
        self.params = system_setup["params"]
        self.A = system_setup["A"]
        self.T_A = system_setup["T_A"]  # Master Trapdoor (used for simulation only)
        
        # Binary Tree parameters for Time Management
        self.tree_depth = system_setup["tree"].depth
        self.total_epochs = 2 ** self.tree_depth
        self.tree_root = system_setup["tree"].root


    # --------------------------------------------
    # 1. Forward Security: Minimal Cover Mechanism
    # --------------------------------------------
    
    def get_min_cover(self, current_time):
        """
        Calculates the Minimal Cover for Forward Security.
        Returns the minimal set of tree nodes required to cover the range [current_time, end].
        
        Logic:
            - A user holding keys for this set can derive keys for any time t >= current_time.
            - They CANNOT derive keys for any time t < current_time (Forward Secrecy).
            
        Args:
            current_time (int): The current time epoch (0 to total_epochs - 1).
            
        Returns:
            list: Sorted list of node labels (integers).
        """
        cover_nodes = []
        target_range = (current_time, self.total_epochs - 1)
        
        def _traverse(node, range_start, range_end):
            if node is None:
                return

            # Midpoint logic matching P1's tree construction
            mid = (range_start + range_end) // 2

            # Case 1: Node is completely in the PAST. Stop.
            if range_end < target_range[0]:
                return

            # Case 2: Node is completely in the FUTURE (or covers current).
            # This node covers the entire remaining subtree needed. Take it.
            if range_start >= target_range[0]:
                cover_nodes.append(node.label)
                return

            # Case 3: Partial Overlap (Current Time splits this node).
            # We must split execution. We cannot hold the parent key because it covers the past.
            # We recurse to specific children.

            # Recurse Left: [start, mid - 1]
            if mid - 1 >= range_start:
                _traverse(node.left, range_start, mid - 1)
            
            # Check the Node itself (Time = mid). 
            # If the specific time 'mid' is in our target range, we need this key.
            if mid >= target_range[0] and mid <= target_range[1]:
                cover_nodes.append(node.label)

            # Recurse Right: [mid + 1, end]
            if mid + 1 <= range_end:
                _traverse(node.right, mid + 1, range_end)

        _traverse(self.tree_root, 0, self.total_epochs - 1)
        
        # Sort for deterministic output
        return sorted(cover_nodes)


    # --------------------------------------------
    # 2. Forward Security: Key Update
    # --------------------------------------------

    def Update(self, current_key_bundle, current_time):
        """
        Evolves the user's secret keys from time t to t+1.
        
        Crucial Step for Forward Security:
            - Calculates the new set of required nodes (MinCover for t+1).
            - Discards old keys that are no longer in the cover.
        
        Args:
            current_key_bundle (dict): {node_label: secret_vector}
            current_time (int): Current time epoch t.
            
        Returns:
            tuple: (new_key_bundle, needed_nodes_list)
        """
        next_time = current_time + 1
        
        # Stop if we reached the end of time
        if next_time >= self.total_epochs:
            return {}, []

        # 1. Get the new minimal cover for t+1
        needed_nodes = self.get_min_cover(next_time)
        new_key_bundle = {}

        # 2. Filter keys: Keep existing valid keys
        for node_label in needed_nodes:
            if node_label in current_key_bundle:
                # Reuse existing key
                new_key_bundle[node_label] = current_key_bundle[node_label]
            else:
                # Key needs to be derived (Delegation).
                # In this simulation, P4/Driver code will handle generating new keys
                # using the 'simulate_key_evolution' helper.
                pass 
                
        return new_key_bundle, needed_nodes

    def simulate_key_evolution(self, user_id, needed_nodes):
        """
        Helper for Simulation: Generates actual secret keys for a list of nodes.
        
        Real-World Note:
            In a full HIBE, child keys are derived from parent keys using basis delegation.
            Here, we simulate this by using P1.SamplePre (Root Extraction) to generate
            valid keys for the target nodes directly. This maintains the security workflow.
        """
        new_bundle = {}
        for node_label in needed_nodes:
            # Create unique identity for this specific Node + User
            unique_str = f"{user_id}_{node_label}"
            
            # Map ID to lattice vector u
            u = P1.G_vector(unique_str, self.params)
            
            # Generate Secret Key e such that A*e = u
            sk = P1.SamplePre(self.A, self.T_A, u, self.params)
            new_bundle[node_label] = sk
            
        return new_bundle


    # --------------------------------------------
    # 3. Cryptography: Encryption (Dual Regev)
    # --------------------------------------------

    def Encrypt(self, target_id, time_epoch, message_bit):
        """
        Encrypts a single bit (0 or 1) for a specific User at a specific Time.
        
        Algorithm: Dual Regev Encryption
        Args:
            target_id (str): Recipient's ID (e.g., "Alice").
            time_epoch (int): The specific time slot t for decryption.
            message_bit (int): 0 or 1.
            
        Returns:
            dict: Ciphertext structure {'c1': vector, 'c2': scalar, ...}
        """
        # 1. Map Target (Identity + Time) to Lattice Vector u
        leaf_node_label = time_epoch
        unique_str = f"{target_id}_{leaf_node_label}"
        u = P1.G_vector(unique_str, self.params)

        # 2. Get Lattice Dimensions
        # Note: A is [A_bar | G], so its width is larger than n.
        n_rows, m_cols = self.A.shape  
        q = self.params.q

        # 3. Generate Randomness (LWE Secret s and Errors e)
        s = np.random.randint(0, q, size=n_rows)
        e1 = P1.discrete_gaussian((m_cols,), self.params.sigma) # Noise vector
        e2 = P1.discrete_gaussian((1,), self.params.sigma)[0]   # Noise scalar

        # 4. Compute Ciphertext Components
        # c1 = A^T * s + e1
        c1 = (self.A.T @ s + e1) % q
        
        # c2 = u^T * s + e2 + message_encoding
        # Encoding: 0 -> 0, 1 -> q/2
        message_scaling = (q // 2) * int(message_bit)
        c2 = (np.dot(u, s) + e2 + message_scaling) % q

        return {
            "c1": c1, 
            "c2": c2, 
            "epoch": time_epoch,
            "target_id": target_id
        }


    # --------------------------------------------
    # 4. Cryptography: Decryption
    # --------------------------------------------

    def Decrypt(self, ciphertext, key_bundle):
        """
        Decrypts ciphertext using the user's current key bundle.
        
        Args:
            ciphertext (dict): The output of Encrypt.
            key_bundle (dict): The user's current set of keys.
            
        Returns:
            int: Decrypted bit (0 or 1), or None if decryption fails.
        """
        c1 = ciphertext["c1"]
        c2 = ciphertext["c2"]
        target_epoch = ciphertext["epoch"]

        # 1. Find the correct key for this epoch
        # The bundle contains keys for nodes that cover the current/future time.
        # We look for a key that matches the target_epoch.
        decryption_key = None
        
        if target_epoch in key_bundle:
            decryption_key = key_bundle[target_epoch]
        else:
            # Fallback scan (if exact key isn't indexed directly)
            for node_label, sk in key_bundle.items():
                if node_label == target_epoch:
                    decryption_key = sk
                    break
        
        if decryption_key is None:
            # Forward Security Check: If we don't have the key, we can't decrypt.
            # This happens if the ciphertext is for a past epoch we've deleted.
            return None

        # 2. Perform Regev Decryption
        # Compute inner product <sk, c1>
        inner = np.dot(decryption_key, c1) % self.params.q
        
        # Remove the mask: approx_message = c2 - inner
        approx_message = (c2 - inner) % self.params.q
        
        # 3. Threshold Decoding
        # Distance to 0 vs Distance to q/2
        center = self.params.q // 2
        
        # Handle modular wraparound for distance to 0
        dist_0 = min(approx_message, self.params.q - approx_message)
        dist_1 = abs(approx_message - center)
        
        # Return closer value
        return 0 if dist_0 < dist_1 else 1


# ============================================
# Unit Testing Block
# ============================================
if __name__ == "__main__":
    print("="*60)
    print("Testing P2: UserOps (Forward Security & Crypto)")
    print("="*60)
    
    # 1. Setup P1 System (Small parameters for fast testing)
    print("\n[1] Initializing System (P1 Setup)...")
    params = P1.LatticeParams(n=256, q=3329)
    system = P1.Setup(tree_depth=3, params=params) # 8 Epochs (0-7)
    
    user_ops = UserOps(system)
    user_id = "Alice"
    print("    System Ready. Tree Depth: 3 (8 Epochs)")

    # 2. Test MinCov Logic
    print("\n[2] Testing Minimal Cover Logic...")
    t = 2
    cover = user_ops.get_min_cover(t)
    print(f"    Minimal cover for T={t} (Expected range [{t}, 7]): {cover}")
    
    # 3. Test Key Evolution
    print("\n[3] Testing Key Evolution (Update)...")
    
    # Simulate T=0 Key Generation
    initial_cover = user_ops.get_min_cover(0)
    current_keys = user_ops.simulate_key_evolution(user_id, initial_cover)
    print(f"    Keys at T=0: {list(current_keys.keys())}")
    
    # Evolve to T=1
    new_keys_bundle, needed = user_ops.Update(current_keys, 0)
    # Simulate the "Server" generating the new needed keys
    current_keys = user_ops.simulate_key_evolution(user_id, needed)
    print(f"    Keys at T=1: {list(current_keys.keys())}")
    
    # 4. Test Encryption & Decryption
    print("\n[4] Testing Cryptography (Dual Regev)...")
    msg = 1
    epoch = 1
    
    print(f"    Encrypting Message '{msg}' for Epoch {epoch}...")
    ct = user_ops.Encrypt(user_id, epoch, msg)
    
    print(f"    Decrypting with T=1 Keys...")
    decrypted = user_ops.Decrypt(ct, current_keys)
    print(f"    Result: {decrypted}")
    
    if decrypted == msg:
        print("\n TEST PASSED: Decryption successful.")
    else:
        print("\n TEST FAILED: Decryption mismatch.")