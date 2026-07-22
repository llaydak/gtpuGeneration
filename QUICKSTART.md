# GTP-U Fuzzing Study: Quick Start 

## Prerequisites Check


# pip packages (minimal)
pip3 install --upgrade pip
pip3 install requests scapy numpy dataclasses
pip3 install psutil  # Optional: for better monitoring



## Step 2: Run Starter Code

```bash
cd ~
python3 phase1_starter.py

# Expected output:
# ======================================================================
# Phase 1: Mistral + GTP-U Mutation + Monitoring Setup
# ======================================================================
# [1/5] Initializing Mistral...
# [OK] Mistral is running
# [2/5] Testing Mistral generation...
# [OK] Generated mutation: {...}
# [3/5] Testing packet builder...
# [OK] Built packet (hex): 30 00 00 1d 00 00 00 01 85 01 20 03 00
#      Valid schema: True
# [4/5] Testing monitoring...
# [OK] Collected 5 measurements
# [5/5] Running 5 quick iterations...
# --- Iteration 1 ---
# Generated: QFI=45, RQI=0, Type=qfi_qer_mismatch
# Valid: True
# ...
# ======================================================================
# Phase 1 Initialization Complete
# ======================================================================
```

**If you see [OK] for all steps: you're ready for Phase 2.**

## Step 3: Verify Mistral Quality (15 minutes)

Run this interactive test to check if Mistral is giving consistent, valid JSON:

```python
# test_mistral_quality.py
import sys
sys.path.insert(0, '/home/claude')
from phase1_starter import MistralClient
import json

mistral = MistralClient()

# Test 10 mutations
for i in range(10):
    ctx = {
        "active_qfis": [0, 15, 32],
        "active_qers": [0, 15, 20],
        "known_anomalies": ["qfi_mismatch"]
    }
    result = mistral.generate_mutation(ctx)
    
    if result:
        print(f" Iteration {i+1}: QFI={result.get('qfi')}, Type={result.get('anomaly_type')}")
        # Check validity
        qfi = result.get('qfi')
        if not (0 <= qfi <= 63):
            print(f" Invalid QFI: {qfi}")
    else:
        print(f"Iteration {i+1}: Failed to parse JSON")

print("\nIf >80% success rate: Mistral is good for zero-shot")
```

## Step 4: Testbed Preview (Optional, for planning)

If you have free5GC or Open5GS ready:

```bash
# Peek at testbed (don't start yet)
docker ps | grep free5gc  # or open5gs
# OR
lsof -i :8000  # Check if any core network running

# Later (Phase 2):
# - Start free5GC with gtp5g module
# - Attach monitor to UPF PID
# - Send actual packets via socket
```

## Troubleshooting

### "JSON parsing failed"
This is normal if Mistral generates markdown or extra text. The code has a fallback.
Check the raw response:
```python
from phase1_starter import MistralClient
m = MistralClient()
raw = m.generate("Respond with JSON: {\"test\": 1}")
print(repr(raw))  # See exact output
```

### "psutil not found"
```bash
pip3 install psutil
# Or live without it (monitoring will just log: "UPF metrics unavailable")
```

## What's Happening Under the Hood

1. **phase1_starter.py**
   - `MistralClient`: Talks to ollama API
   - `GTP_U_Mutation`: Dataclass holding one packet mutation
   - `GTP_U_Packet_Builder`: Converts mutation → GTP-U bytes
   - `UPF_Monitor`: Placeholder for testbed feedback (Phase 2)

2. **Prompt Flow**
   ```
   Context (QFI=[0,15,32], QER=[0,15,20])
   → Mistral prompt (evidence-grounded)
   → JSON response ({"qfi": X, "rqi": Y, ...})
   → Validation (0 <= qfi <= 63)
   → Packet bytes
   → (Later) Send to testbed, measure anomaly
   ```

3. **Zero-Shot Strategy**
   - No fine-tuning yet
   - Prompt structure = your "evidence bound"
   - Mistral is a reasoning engine, not a classifier

## What to Do by End of Week 1

- [ ] Run `phase1_starter.py` successfully
- [ ] Verify Mistral JSON output is valid & consistent
- [ ] Understand packet hex format (debug output)
- [ ] Read through `GTP_U_Fuzzing_Roadmap.md` sections 1-2
- [ ] Start sketching Knowledge Graph schema (pen & paper OK)


