# LLM-Guided GTP-U Fuzzing: START HERE


```
/home/claude/
├── QUICKSTART.md                          ← First 1-2 hours of work
├── phase1_starter.py                      ← Working Python code 
├── GTP_U_Fuzzing_Roadmap.md              ← 12-week detailed plan
└── Semantics_to_GTP_U_Mapping.md         ← How Semantics paper informs your work
```

---

## Reading Order

### **Right Now (Next 15 minutes)**
2. **QUICKSTART.md** — 5 steps to get Mistral running
3. **phase1_starter.py** — Skim the code structure 

### **This Week (Hafta 1)**
1. Run `python3 phase1_starter.py` ✓
2. Verify Mistral generates valid JSON 5+ times ✓
3. Read **GTP_U_Fuzzing_Roadmap.md** Sections 1-2 (grounding & knowledge graph intro)
4. Read **Semantics_to_GTP_U_Mapping.md** — understand how paper's methodology applies to your work

| File | Purpose | When to Read | Time |
|---|---|---|---|
| **QUICKSTART.md** | Setup instructions + troubleshooting | Before running phase1_starter.py | 30 min |
| **phase1_starter.py** | Working code: Mistral + Scapy + Monitoring | Run Week 1, then extend | - |
| **GTP_U_Fuzzing_Roadmap.md** | Detailed 12-week plan with code snippets | Reference throughout study | 2-3 hours total |
| **Semantics_to_GTP_U_Mapping.md** | How Semantics paper ↔ your study | After understanding phase1_starter | 1 hour |

---

## Your First Actionable Checklist (Next 2 Hours)

- [ ] Read QUICKSTART.md (15 min)
- [ ] Run phase1_starter.py in Terminal 2 (10 min)
- [ ] See `[OK]` on all 5 steps → success! (you'll know in 5 sec)
- [ ] Read QUICKSTART "Troubleshooting" section if anything fails (10 min)
- [ ] Run test_mistral_quality.py snippet from QUICKSTART (5 min)
- [ ] Record: "Mistral JSON success rate = X%"
- [ ] Skim Roadmap.md sections 1.1-1.3 (20 min)

**Total: ~2 hours, mostly waiting for Mistral to install.**

---

##  Work Cycle (Repeat Each Week)

```
Week N:
1. Read Roadmap section N
2. Implement code from that section
3. Test on offline Mistral
4. If next week needs testbed: start setting up free5GC/Open5GS
5. Record metrics (success rate, execution time, issues)
6. Move to next section

Example (Week 1):
1. Read Roadmap § 1.1 (Mistral setup) ✓
2. phase1_starter.py = implementation ✓
3. Test: Mistral 10/10 JSON valid ✓
4. Week 2 prep: Start thinking about Knowledge Graph schema ✓
5. Metrics: "Zero-shot success 100%, avg response time 1.2 sec"
```

---

## Mistral vs. Your Other Offline Models

You mentioned having several offline models and Mistral was best for **zero-shot** in Report1.

**What this means for you**:
- Mistral = no fine-tuning needed → start now
- Other models = might need examples/prompts → save for Phase 3
- Comparison table coming in Roadmap § 5 (prompt strategies)

**Strategy**:
```
Weeks 1-4:  Pure Mistral zero-shot (no tuning)
Weeks 5-8:  Compare Mistral vs. your other models
Week 9-10:  Fine-tune Mistral on validated outputs (if needed)
```

---

## Key Concepts

### Evidence-Bounded LLM

**How**: Prompt = spec text + field ranges + session state (nothing else)
**Why**: Prevents hallucinations; every mutation is traceable to 3GPP spec

### DSL (Domain-Specific Language)
**What**: Mini-language for describing GTP-U field rules
**Example**: `EQ(qfi, active_qer_id)` = "QFI must equal one of the active QER IDs"
**Your version**: Just JSON with {field: value, constraint: relation}

### Knowledge Graph
**What**: Node = protocol concept (QFI, RQI, etc.). Edge = relationship
**Purpose**: Tracks what you've explored, guides next mutation
**Phase 2**: You'll sketch this; Phase 3 you'll query it

### Agentic Loop
**What**: Mutation → Testbed → Feedback → Next Mutation (repeat)
**Phase**: Weeks 5-6 in Roadmap
**Key**: Feedback (anomaly detected?) informs which region of field space to explore next



### Step 1: Open Terminal 1
```bash
# Install ollama (if not already done)
# From https://ollama.ai
# Then:
ollama pull mistral
ollama serve
# Wait for: Listening on 127.0.0.1:11434
```

### Step 2: Open Terminal 2
```bash
cd /home/claude
# Read QUICKSTART
cat QUICKSTART.md | less

# Run the test
python3 phase1_starter.py
```

### Step 3: Check the Output
```
Look for:
  ✓ [OK] Mistral is running
  ✓ [OK] Generated mutation: {...}
  ✓ [OK] Built packet (hex): ...
  ✓ [OK] Collected N measurements

If you see all 4 [OK]: **YOU'RE READY**
```

### Step 4: Record Your Result
```
Success rate: ___/5 ✓
Mistral response time: ___ seconds
Packet hex length: ___ bytes
Next step: Read GTP_U_Fuzzing_Roadmap.md § 2
```

---

##If You Get Stuck

1. **First**: Check QUICKSTART.md "Troubleshooting" section
2. **Second**: Verify Mistral is running: `curl http://localhost:11434/api/tags`
3. **Third**: Run test_mistral_quality.py from QUICKSTART



- JSON parsing failed → Normal; fallback works
- Port 11434 already in use → Change in phase1_starter.py line with `base_url`



## 🚦 Timeline Summary

| Weeks | Milestone | Status |
|---|---|---|
| 1-2 | Mistral + Scapy working, initial mutation generation | 📋 This week |
| 3-4 | Knowledge graph + vector store from specs | 📅 Next 2 weeks |
| 5-6 | Agentic feedback loop on free5GC testbed | 📅 Weeks 5-6 |
| 7-8 | Baseline comparisons (grammar, GAN, known attacks) | 📅 Mid-term |
| 9-10 | Prompt strategy comparison (A vs B vs C) | 📅 Late-term |
| 11-12 | Evaluation metrics + paper writing | 📅 Final sprint |

**August 24 = 8 weeks away from now.** You're on track if you start *today*.

---

**Build an offline LLM-guided fuzzer that generates semantic GTP-U anomalies more effectively than random mutation, validated on a 5G testbed, with evidence grounded in 3GPP specs.**


