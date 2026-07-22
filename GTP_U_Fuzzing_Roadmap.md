# LLM-Guided GTP-U Fuzzing Çalışması: Pratik Yol Haritası

### **FAZA 1: Setup & Grounding (Şubat 1-2 Hafta)**
*Amaç: Offline model ve testbed üzerinde temel loop'u çalıştırmak*

#### 1.1 Offline Model Seçimi ve Evaluation
- [ ] Mistral (en iyi zero-shot sonuç, Report1'de kullandığın)
- [ ] Eğer gerek varsa OpenHermes-2.5, Neural-Chat (Mistral variants)
- [ ] İlk test: "TS 29.281'e göre QFI-QER mismatch nedir?" prompt'u
  ```bash
  # Setup
  pip install ollama mistral-model  # veya ollama pull mistral
  # Quick test
  cat << 'EOF' > test_prompt.py
  import requests
  
  prompt = """You are a 5G protocol expert. 
  TS 29.281 defines QFI (QoS Flow Identifier) and 3GPP TS 29.244 defines QoS Enforcement Rules.
  When a GTP-U packet contains a QFI value that has NO corresponding QER in the current session,
  what kind of semantic anomaly is this? Respond in JSON with: 
  {"anomaly_type": "...", "expected_field_behavior": "...", "fields_involved": [...]}
  """
  
  response = requests.post(
    "http://localhost:11434/api/generate",
    json={"model": "mistral", "prompt": prompt, "stream": False}
  )
  print(response.json()["response"])
  EOF
  python test_prompt.py
  ```

#### 1.2 Testbed Minimal Setup
- [ ] **free5GC + gtp5g kernel module** (Docker'da)
  ```bash
  git clone https://github.com/free5gc/free5gc.git
  cd free5gc && make -j $(nproc)  # ~30 min
  # Veya: docker pull free5gc/base:ubuntu
  ```
- [ ] **Open5GS** (backup olarak)
  ```bash
  docker pull open5gs/open5gs:latest
  ```
- [ ] **Monitoring baseline**: UPF RAM, CPU, gtp5g kernel errors
  ```bash
  # Monitoring script
  cat << 'EOF' > monitor_upf.sh
  #!/bin/bash
  while true; do
    echo "=== $(date) ==="
    ps aux | grep upf | grep -v grep | awk '{print $2, $3, $4}' # PID CPU MEM
    dmesg | tail -3 | grep -i gtp
    sleep 2
  done
  EOF
  ```

#### 1.3 Scapy Extension Header Wrapper
- [ ] GTP-U PDU Session Container'ı Scapy'de struct'a dönüştür
  ```python
  from scapy.all import *
  
  class GTP_U_PDUSessionContainer(Packet):
      name = "GTP-U PDU Session Container"
      fields_desc = [
          BitField("extension_header_type", 0x85, 8),  # 5G
          BitField("spare", 0, 4),
          BitField("pdu_type", 1, 4),  # DL/UL
          ByteField("qfi", 0),  # 0-63 valid
          ConditionalField(ByteField("rqi", 0), lambda pkt: pkt.qfi < 64),
          ConditionalField(ByteField("ppi", 0), lambda pkt: pkt.qfi < 64),
          # ... pdu_set marker for Rel 18
      ]
  ```

#### 1.4 Minimum Viable Prompt Loop
- [ ] Spec parça + field definitions → Mistral → JSON mutation candidate
  ```python
  # spec_fragment = "TS 29.281: QFI identifies a QoS flow within a PDU session..."
  # fields = {"qfi": 32, "qer_active": [0, 15, 20], "ppi": None}
  # Mistral'a sor: "Bu sessionda QFI=32 var ama active QER'ler [0,15,20]'de.
  # QFI=32 için anomaly yaratacak bir mutation yap."
  ```

---

### **FAZA 2: Knowledge Graph v0.1 (Hafta 3-4)**
*Amaç: Setin taxonomisi ve relational structure'ı oluşturmak*

#### 2.1 Knowledge Graph Nodes
- [ ] **Protocol structure nodes**: 
  ```json
  {
    "nodes": {
      "QFI": {
        "range": [0, 63],
        "depends_on": ["PDU_Session", "QER"],
        "spec": "TS 29.281 § 5.1.6",
        "semantics": "Identifies QoS flow within session"
      },
      "RQI": {
        "range": [0, 1],
        "depends_on": ["QER", "QFI"],
        "spec": "TS 29.281 § 5.1.7",
        "semantics": "Reflective QoS Indicator"
      },
      "PPI": {
        "range": [0, 7],
        "depends_on": ["Traffic_Class"],
        "spec": "TS 29.281 § 5.1.8",
        "semantics": "Paging Policy Indicator"
      }
    }
  }
  ```

- [ ] **Taxonomy nodes**: (MITRE FiGHT + OWASP 2025'ten)
  ```python
  taxonomies = {
      "resource_exhaustion": ["QFI abuse", "header chain loop", "amplification"],
      "policy_bypass": ["QFI-QER mismatch", "unauthorized QER access"],
      "design_flaw": ["pdu_set race", "timing window"],
      "exceptional_handling": ["invalid chaining", "unsupported marker"]
  }
  ```

- [ ] **Precedent nodes**: (CVE + 5G-Attacks dataset)
  ```json
  {
    "CVE-2023-23846": {
      "affected_fields": ["extension_header"],
      "vulnerability": "infinite_loop",
      "trigger": "malformed_length",
      "taxonomy": "exceptional_handling"
    },
    "CVE-2025-29646": {
      "affected_fields": ["teid"],
      "vulnerability": "resource_exhaustion",
      "trigger": "pfcp_timing_race",
      "taxonomy": "policy_bypass"
    }
  }
  ```

#### 2.2 Vector Store Setup (RAG foundation)
- [ ] **Spec chunks**: TS 29.281, 29.244 sections →  text chunks
  ```python
  from langchain.document_loaders import PDFLoader
  from langchain.text_splitter import RecursiveCharacterTextSplitter
  
  loader = PDFLoader("TS_29.281.pdf")
  docs = loader.load()
  splitter = RecursiveCharacterTextSplitter(chunk_size=512, overlap=50)
  chunks = splitter.split_documents(docs)
  
  # Vector embedding: ONNX-based offline (no API needed)
  from sentence_transformers import SentenceTransformer
  model = SentenceTransformer('all-MiniLM-L6-v2')  # ~80MB
  embeddings = [model.encode(chunk.page_content) for chunk in chunks]
  ```

- [ ] **Vector DB** (Faiss, Chroma, veya basit pickle)
  ```python
  import faiss
  embedding_matrix = np.array(embeddings).astype('float32')
  index = faiss.IndexFlatL2(embedding_matrix.shape[1])
  index.add(embedding_matrix)
  faiss.write_index(index, "spec_index.faiss")
  ```

#### 2.3 Retrieval Sanity Check
- [ ] Query: "QFI and QER relationship" → top 3 chunks dönsün
  ```python
  query_embedding = model.encode("QFI and QER dependency relationship")
  D, I = index.search(np.array([query_embedding]).astype('float32'), 3)
  for idx in I[0]:
    print(chunks[idx].page_content)
  ```

---

### **FAZA 3: Agentic Loop v0.1 (Hafta 5-6)**
*Amaç: Mutation → packet → testbed → feedback cycle'ını kurmak*

#### 3.1 Feedback Collection Infrastructure
```python
import subprocess
import time
import psutil

class UPF_Monitor:
    def __init__(self, upf_pid):
        self.upf_pid = upf_pid
        self.baseline = {
            "memory": psutil.Process(upf_pid).memory_info().rss,
            "cpu_percent": psutil.Process(upf_pid).cpu_percent()
        }
    
    def measure_after_packet(self, packet, duration=2):
        # Send packet
        send(packet)
        
        # Collect metrics for 2 sec
        time.sleep(0.5)  # Propagation
        metrics = {}
        for t in range(duration * 10):
            proc = psutil.Process(self.upf_pid)
            metrics[t] = {
                "memory": proc.memory_info().rss,
                "cpu": proc.cpu_percent(),
                "alive": proc.is_running()
            }
            time.sleep(0.1)
        
        # Check for anomaly
        if metrics[-1]["memory"] > self.baseline["memory"] * 1.5:
            return {"anomaly": "memory_leak", "severity": "high"}
        if not metrics[-1]["alive"]:
            return {"anomaly": "crash", "severity": "critical"}
        if any(m["cpu"] > 80 for m in metrics.values()):
            return {"anomaly": "cpu_spike", "severity": "medium"}
        
        return {"anomaly": "none", "severity": 0}
```

#### 3.2 Generation + Execution Loop
```python
class Agentic_GTP_U_Fuzzer:
    def __init__(self, mistral_client, upf_monitor, knowledge_graph, vector_store):
        self.llm = mistral_client
        self.monitor = upf_monitor
        self.kg = knowledge_graph
        self.vs = vector_store
        self.history = []  # mutations + outcomes
    
    def step(self):
        # 1. Pick unexplored KG region
        target_node = self.kg.get_unexplored_or_related_to_recent_effect()
        
        # 2. Retrieve relevant spec text
        query = f"How should {target_node['field']} behave given constraints?"
        relevant_docs = self.vs.retrieve(query, k=3)
        
        # 3. LLM mutation proposal
        prompt = f"""
        Given:
        - Target field: {target_node['field']} (range: {target_node['range']})
        - Current session state: QFI=[0,15,32], QER=[0,15,20]
        - Spec context: {relevant_docs}
        
        Generate a GTP-U packet with a semantic anomaly that could trigger {target_node['taxonomy']}.
        Respond ONLY with JSON: {{"qfi": int, "rqi": int, "ppi": int, "reasoning": str}}
        """
        
        mutation_json = self.llm.generate(prompt)
        
        # 4. Construct packet
        pkt = construct_gtp_u_packet(mutation_json)
        
        # 5. Send to UPF
        anomaly = self.monitor.measure_after_packet(pkt)
        
        # 6. Store + feed back
        self.history.append({
            "mutation": mutation_json,
            "outcome": anomaly,
            "timestamp": time.time()
        })
        
        # 7. If anomaly detected, refine
        if anomaly["severity"] > 0:
            self.kg.mark_node_as_productive(target_node)
            # Next iteration: focus on similar mutations
            return "refine"
        else:
            self.kg.mark_node_as_explored(target_node)
            return "sample_new"
```

---

### **FAZA 4: Baseline Generators (Hafta 7-8)**
*Amaç: LLM'nin katkısını measure etmek*

#### 4.1 Grammar-Based Fuzzer
```python
# Fuzzowski style: random field mutations
class Grammar_Fuzzer:
    def generate(self):
        pkt = {
            "qfi": random.randint(0, 63),  # Always valid range
            "rqi": random.randint(0, 1),
            "ppi": random.randint(0, 7)
        }
        return pkt  # No semantic reasoning
```

#### 4.2 GAN Baseline
```python
# Torch-based, small GAN trained on valid session traces
class GAN_Generator(torch.nn.Module):
    def __init__(self):
        super().__init__()
        self.fc = torch.nn.Linear(100, 3)  # latent → [qfi, rqi, ppi]
    
    def forward(self, z):
        return torch.clamp(self.fc(z), 0, 63)  # Clamp to ranges
```

#### 4.3 Known-Attack Replay
```python
# CVE-2025-29646, CVE-2023-23846 replay
known_attacks = [
    {"qfi": 255, "rqi": 2, "ppi": 8},  # out of bounds
    {"extension_header": [0x85, 0x85]},  # duplicate chain
]
```

---

### **FAZA 5: Prompt Strategy Comparison (Hafta 9-10)**
*Amaç: Retrieval + feedback'in impact'ını ölçmek*

#### 5.1 Three Conditions
```
Condition A (Baseline):
  - Prompt: Just spec + field ranges, no retrieval
  - Output: mutation JSON
  - Metric: success rate (packet constructed)

Condition B (RAG + Agentic):
  - Prompt: spec + retrieval docs + KG context + prior feedback
  - Output: mutation JSON
  - Metric: effect rate (anomaly detected)

Condition C (Fine-tuned, if data enough):
  - Mistral fine-tuned on Condition B outputs marked "effective"
  - Metric: effect rate (should be ≥ Condition B)
```

#### 5.2 Comparative Run
```python
results = {
    "condition_a": {
        "packets_generated": 200,
        "schema_valid": 195,
        "effects_triggered": 12,
        "novelty": 0.8  # % not in precedent set
    },
    "condition_b": {
        "packets_generated": 200,
        "schema_valid": 200,
        "effects_triggered": 58,  # Expected improvement
        "novelty": 0.92
    }
}
```

---

### **FAZA 6: Evaluation Framework & Report (Hafta 11-12)**
*Amaç: Sonuçları Semantics paper gibi structure'da raporlamak*

#### 6.1 Multi-Dimensional Metrics
- **Schema validity rate**: (packets re-encoded successfully) / total
- **Policy-consistency deviation**: QFI-QER mismatch % in generated
- **Novelty**: % not in 5G-Attacks + CVE replay set
- **Repetition rate**: Duplicate mutations per condition
- **Testbed effect rate**: (anomalies detected) / (packets sent)
- **Detection evasion rate**: (effects not caught by basic IDS) / (effects)
- **Graph coverage rate**: (explored KG nodes) / (total nodes)

#### 6.2 Anomaly Taxonomy Table
```
| Attack Type | Packets Generated | Effects | Novelty % |
|---|---|---|---|
| QFI-QER mismatch | 45 | 23 | 91% |
| Extension header chaining | 38 | 15 | 87% |
| Cross-flow interference | 52 | 18 | 85% |
| PDU Set abuse | 40 | 8 | 94% |
| Timing window | 25 | 12 | 100% |
```

---

## **İlk 1-2 Hafta İçin Immediate Todos**

### **Hafta 1, Gün 1-3: Setup**
```bash
# 1. Offline Mistral kurup test et
ollama pull mistral
# 2. free5GC kurulum başlat (container olarak)
docker run -it free5gc/base:ubuntu bash
# 3. Scapy PDU Session Container extension başla
python3 << 'EOF'
from scapy.all import Packet, BitField, ByteField
# Draft your GTP-U extension class here
EOF
```

### **Hafta 1, Gün 4-7: Grounding**
```bash
# 1. Specification PDFs'i chunk'la ve vector DB'ye koy
python3 -m pip install sentence-transformers faiss-cpu langchain
# 2. Retrieval sanity check: "QFI relationship" query
# 3. Monitor script'i free5GC UPF'ye bağla
# 4. Prompt v1'ini test et: "Given this spec, what's a QFI-QER mismatch?"
```

### **Hafta 2: Minimal Loop**
```bash
# 1. Agentic loop skeleton'u yaz (above code'dan adapte et)
# 2. Mutation JSON → Scapy packet → send()'e kadar test et
# 3. Baseline grammar fuzzer ve known-attack replay'i implement et
# 4. Örnek 10 packet'i manual olarak her approach ile generate et ve karşılaştır
```

---

## **Mistral Zero-Shot Performans İçin Tips**

Report1'de "Mistral en iyi zero-shot" dediğine göre, bunları şimdi test et:

1. **Structured output encouragement**:
   ```python
   prompt = """
   Respond ONLY with JSON, no markdown, no explanation:
   {"qfi": <int 0-63>, "rqi": <int 0-1>, "ppi": <int 0-7>, "anomaly_type": "<str>"}
   """
   ```

2. **In-context few-shots**:
   ```python
   examples = [
       {"input": "QFI should link to active QER", "output": {"qfi": 50, "qer_ids": [0,15], "anomaly": "orphaned_qfi"}},
       {"input": "Extension chain must be valid", "output": {"chain": [0x85, 0x00], "anomaly": "invalid_chain"}}
   ]
   ```

3. **Specification-grounding**:
   ```python
   prompt = """
   According to 3GPP TS 29.281 Section 5.1.6:
   'QFI identifies a QoS flow within a PDU session.'
   
   If a packet has QFI=50 but no corresponding QER with QER-ID=50,
   is this a valid GTP-U packet?
   ```

---

## **Expected Outcomes After 12 Weeks**

- ✅ Offline Mistral loop çalışıyor
- ✅ free5GC testbed'de crashes/anomalies capture ediliyor
- ✅ 3 conditions karşılaştırılmış, LLM benefit clear
- ✅ 50-150 novel GTP-U mutation patterns documented
- ✅ Semantics paper'dan metodoloji uygulanmış, kendin için adapted

---

## **Semantics Paper'dan Alınacak Spesifik Patterns**

| Semantics Technique | Your Adaptation | Implementation |
|---|---|---|
| Evidence-bounded LLM | Spec fragments → Mistral (no external knowledge) | Prompt'ta sadece TS 29.281/244 snippet'leri |
| DSL Normalization | GTP-U field rules DSL | JSON → validate ranges, dependencies |
| Dual abstraction | Packet structure + field table | Scapy object + constraint dict |
| Minimal edits | Single field perturbation | One QFI/RQI/PPI change per packet |
| Re-encoding check | Scapy re-construct | pkt.show() after modification |
| Agentic refinement | Feedback loop | Monitor outcome → refine KG → next mutation |

---

**Sorun ya da stuck kalırsan, bu dosyayı referans olarak kullan.**
