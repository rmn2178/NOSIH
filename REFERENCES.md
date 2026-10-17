# References & Authoritative Evidence Registry (`REFERENCES.md`)

**Project:** NOSIH (Non-ambient Origin-Scoped Intent Harness)  
**Scope:** Complete bibliographic registry of primary peer-reviewed publications, IETF/Unicode/NIST/OWASP standards, empirical agent security benchmarks, and documented vulnerability advisories cited across the NOSIH research repository.

## 1. Foundational Research & Technical Standards (`[1]`–`[10]`)

* **`[1]`** **Greshake, K., Abdelnabi, S., Mishra, S., Endres, C., Holz, T., & Fritz, M. (2023).** *Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection*. In Proceedings of the 16th ACM Workshop on Artificial Intelligence and Security (AISec '23), pp. 79–90.
  * **Primary Link:** [arXiv:2302.12173](https://arxiv.org/abs/2302.12173) | [PDF](https://arxiv.org/pdf/2302.12173)
  * **Research Role in NOSIH:** Establishes the foundational threat model showing how untrusted external data retrieved by LLM-integrated tools blurs the code/data boundary to hijack downstream tool execution.

* **`[2]`** **Perez, F., & Ribeiro, I. (2022).** *Ignore Previous Prompt: Attack Techniques For Language Models*. NeurIPS ML Safety Workshop / arXiv Preprint.
  * **Primary Link:** [arXiv:2211.09527](https://arxiv.org/abs/2211.09527) | [Semantic Scholar](https://www.semanticscholar.org/paper/Ignore-Previous-Prompt%3A-Attack-Techniques-For-Perez-Ribeiro/9716a2876d08fce9d8e5c5ba4d7b1a9af44806d6)
  * **Research Role in NOSIH:** Formalizes Goal Hijacking and Prompt Leaking primitives, motivating NOSIH's strict Zero-LLM Critical Path (`NFR-02`) and positive origin locks.

* **`[3]`** **Davis, M., & Suignard, M. (Unicode Consortium).** *Unicode Technical Standard #39: Unicode Security Mechanisms*. Unicode Standard Annex / Technical Standard.
  * **Primary Link:** [Unicode UTS #39 Official Specification](https://www.unicode.org/reports/tr39/)
  * **Research Role in NOSIH:** Defines formal confusable detection (`skeleton` mapping), mixed-script identifier restrictions, and normalization profiles used in NOSIH Stage 1 representation diffing.

* **`[4]`** **Davis, M., & Suignard, M. (Unicode Consortium).** *Unicode Technical Report #36: Unicode Security Considerations*. Unicode Consortium Technical Report.
  * **Primary Link:** [Unicode UTR #36 Official Specification](https://www.unicode.org/reports/tr36/)
  * **Research Role in NOSIH:** Characterizes visual homoglyphs, bidirectional (BiDi) overrides (`U+202E`), invisible tag characters (`U+E0000`–`U+E007F`), and non-shortest-form UTF-8 exploits across parser boundaries.

* **`[5]`** **Kent, K., & Souppaya, M. (2006).** *NIST Special Publication 800-92: Guide to Computer Security Log Management*. National Institute of Standards and Technology (NIST), U.S. Department of Commerce.
  * **Primary Link:** [DOI: 10.6028/NIST.SP.800-92](https://doi.org/10.6028/NIST.SP.800-92)
  * **Research Role in NOSIH:** Establishes enterprise baselines for security event generation, audit log retention, and forensic incident reconstruction.

* **`[6]`** **Kelsey, J., Callas, J., & Clemm, A. (2010).** *RFC 5848: Signed Syslog Messages*. Internet Engineering Task Force (IETF), Standards Track.
  * **Primary Link:** [IETF RFC 5848 Specification](https://www.rfc-editor.org/rfc/rfc5848)
  * **Research Role in NOSIH:** Provides the cryptographic hash-chaining and signature-block design patterns adapted in NOSIH's tamper-evident Merkle Provenance Ledger to detect log deletion, alteration, or reordering.

* **`[7]`** **Rundgren, A., Jordan, B., & Erdtman, S. (2020).** *RFC 8785: JSON Canonicalization Scheme (JCS)*. Internet Engineering Task Force (IETF), Informational / Specification Required.
  * **Primary Link:** [IETF RFC 8785 Specification](https://www.rfc-editor.org/rfc/rfc8785)
  * **Research Role in NOSIH:** Establishes invariant, deterministic serialization of JSON data structures (UTF-16 lexicographical key sorting and IEEE 754 number formatting) required for NOSIH's boot-time `schema_lock` digests and per-RPC `verified_args_hash`.

* **`[8]`** **Torres-Arias, S., Afzali, H., Kuppusamy, T. K., Curtmola, R., & Cappos, J. (2019).** *in-toto: Providing Farm-to-Table Guarantees for Bits and Bytes*. In Proceedings of the 28th USENIX Security Symposium (USENIX Security 19), pp. 1393–1410.
  * **Primary Link:** [USENIX Security 19 Presentation & Paper](https://www.usenix.org/conference/usenixsecurity19/presentation/torres-arias) | [Full Paper PDF](https://www.usenix.org/system/files/sec19-torres-arias.pdf)
  * **Research Role in NOSIH:** Inspires NOSIH's Proof-Bearing Telemetry workflow by modeling every artifact normalization step ($\tau_1, \dots, \tau_m$) and Foreign-Key Witness join as signed *link metadata* verified against the declarative `nosih.yaml` *layout*.

* **`[9]`** **OWASP GenAI Security Project (2025).** *OWASP Top 10 for Large Language Model Applications*. Open Worldwide Application Security Project (OWASP).
  * **Primary Link:** [OWASP LLM Top 10 Official Portal](https://genai.owasp.org/llm-top-10/)
  * **Research Role in NOSIH:** Connects academic prompt-injection and sensitive-data-disclosure findings to practical enterprise security controls (`LLM01: Prompt Injection`, `LLM02: Sensitive Information Disclosure`, `LLM06: Excessive Agency`).

* **`[10]`** **OWASP GenAI Security Project (2025).** *OWASP Top 10 for Agentic Applications for 2026 (ASI01–ASI10)*. Open Worldwide Application Security Project (OWASP).
  * **Primary Link:** [OWASP Agentic Top 10 (2026) Resource Page](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  * **Research Role in NOSIH:** Defines the core taxonomy of agentic failures targeted by NOSIH: `ASI01` (Agent Goal Hijack), `ASI02` (Tool Misuse), `ASI03` (Identity & Privilege Abuse), `ASI04` (Supply Chain / Schema Rug Pulls), `ASI06` (Context Poisoning), and `ASI09` (Human-Agent Trust Exploitation).

## 2. Empirical Benchmarks & Second-Generation Agent Defenses (`[11]`–`[18]`)

* **`[11]`** **MCPTox Benchmark Authors (2025–2026).** *MCPTox: A Benchmark for Tool Poisoning Attack on Real-World MCP Servers*. arXiv Preprint `arXiv:2508.14925`.
  * **Primary Link:** [arXiv:2508.14925](https://arxiv.org/abs/2508.14925)
  * **Research Role in NOSIH:** Demonstrates across 45 live MCP servers and 353 authentic tools that tool poisoning and indirect prompt injection achieve up to a **72.8% Attack Success Rate (ASR)** on state-of-the-art frontier LLMs.

* **`[12]`** **Debenedetti, E., Shumailov, I., Fan, T., et al. (2025).** *Defeating Prompt Injections by Design (CaMeL)*. Google DeepMind, arXiv Preprint `arXiv:2503.18813`.
  * **Primary Link:** [arXiv:2503.18813](https://arxiv.org/abs/2503.18813)
  * **Research Role in NOSIH:** Establishes the static dual-LLM (Privileged + Quarantined) capability isolation baseline, achieving 0.0% ASR on static tasks while motivating NOSIH's solution to CaMeL's 0.0% dynamic utility cliff.

* **`[13]`** **Shi, T., et al. (2025–2026).** *Progent: Securing AI Agents with Privilege Control*. UC Berkeley, arXiv Preprint `arXiv:2504.11703`.
  * **Primary Link:** [arXiv:2504.11703](https://arxiv.org/abs/2504.11703)
  * **Research Role in NOSIH:** Establishes the dynamic LLM policy-updating baseline (~420 ms per-step latency overhead) whose vulnerability to second-order prompt injection motivates NOSIH's deterministic Value-Erased Foreign-Key Witness joins.

* **`[14]`** **Li, Y., et al. (2026).** *AgentDyn: Are Your Agent Security Defenses Deployable in Real Open-Ended Environments?*. arXiv Preprint `arXiv:2602.03117`.
  * **Primary Link:** [arXiv:2602.03117](https://arxiv.org/abs/2602.03117)
  * **Research Role in NOSIH:** Evaluates 60 open-ended dynamic tasks and 560 injection cases, proving that static plan-locking defenses such as CaMeL drop to **0.0% task completion utility** when downstream tool calls depend on prior tool outputs.

* **`[15]`** **Amin, R. J. (2026).** *What Defence Numbers Actually Say: Empirical Analysis of Static vs. Dynamic Agent Security Benchmarks*. Technical Benchmark Analysis.
  * **Primary Link:** [Benchmark Analysis Post](https://aminrj.com/posts/what-defence-numbers-actually-say/)
  * **Research Role in NOSIH:** Synthesizes the empirical utility cliff between static benchmarks (`AgentDojo`) and open-ended dynamic benchmarks (`AgentDyn`).

* **`[16]`** **Narisetty, P., et al. (2026).** *Adaptive Evaluation of Out-of-Band Defenses Against Prompt Injection in LLM Agents*. arXiv Preprint `arXiv:2606.26479`.
  * **Primary Link:** [arXiv:2606.26479](https://arxiv.org/abs/2606.26479)
  * **Research Role in NOSIH:** Proves that dynamic defenses relying on an out-of-band LLM to update policies or judge tool calls (such as Progent) are systematically bypassed by adaptive second-order prompt injections.

* **`[17]`** **AutoDojo Research Collective (2026).** *AutoDojo: A Generative Benchmark for Evaluating Prompt Injection Defenses*. arXiv Preprint `arXiv:2606.15057`.
  * **Primary Link:** [arXiv:2606.15057](https://arxiv.org/abs/2606.15057)
  * **Research Role in NOSIH:** Confirms via automated red-teaming that probabilistic and LLM-based runtime policy guardrails degrade sharply under adaptive multi-hop optimization.

* **`[18]`** **Debenedetti, E., Zhang, J., Balunović, M., Beurer-Kellner, L., Fischer, M., & Tramèr, F. (2024).** *AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents*. Advances in Neural Information Processing Systems (NeurIPS 2024), `arXiv:2406.13352`.
  * **Primary Link:** [arXiv:2406.13352](https://arxiv.org/abs/2406.13352)
  * **Research Role in NOSIH:** Provides standardized multi-tool workspace task templates adapted for NOSIH's controlled experimental evaluation methodology.

## 3. Model Context Protocol (MCP) Ecosystem, Identity & Vulnerability Literature (`[19]`–`[26]`)

* **`[19]`** **Gaire, S., et al. (2025).** *Systematization of Knowledge (SoK): Security and Safety in the Model Context Protocol Ecosystem*. arXiv Preprint `arXiv:2512.08290`.
  * **Primary Link:** [arXiv:2512.08290](https://arxiv.org/abs/2512.08290)
  * **Research Role in NOSIH:** Systematizes MCP trust boundaries, tool poisoning, mid-session schema rug pulls, cross-server tool shadowing, and confused-deputy escalation.

* **`[20]`** **MDPI Journal of Cybersecurity and Privacy (2026).** *Model Context Protocol Threat Modeling and Analyzing Vulnerabilities to Prompt Injection with Tool Poisoning*. *Journal of Cybersecurity and Privacy*, 6(3):84 (`arXiv:2603.22489`).
  * **Primary Link:** [MDPI J. Cybersecur. Priv. 6(3):84](https://www.mdpi.com/2624-800X/6/3/84) | [arXiv:2603.22489](https://arxiv.org/abs/2603.22489)
  * **Research Role in NOSIH:** Formalizes protocol-level threat models for JSON-RPC 2.0 tool invocation and confirms the absence of native message-level argument provenance in MCP.

* **`[21]`** **Invariant Labs Research Team (2025).** *MCP Security Notification: Tool Poisoning Attacks & Introducing MCP-Scan*. Invariant Labs Security Advisories.
  * **Primary Link:** [Introducing MCP-Scan](https://invariantlabs.ai/blog/introducing-mcp-scan) | [Tool Poisoning Notification](https://invariantlabs.ai/blog/mcp-security-notification)
  * **Research Role in NOSIH:** Documents static tool-description poisoning and mid-session schema rug pulls, serving as the startup-scanner baseline in NOSIH's comparative evaluation.

* **`[22]`** **MCP Guardian Authors (2025).** *MCP Guardian: A Security-First Layer for Safeguarding MCP-Based AI Systems*. ResearchGate Preprint.
  * **Primary Link:** [ResearchGate Publication 391905340](https://www.researchgate.net/publication/391905340_MCP_Guardian_A_Security-First_Layer_for_Safeguarding_MCP-Based_AI_System)
  * **Research Role in NOSIH:** Establishes the stateless regex WAF and manual human-in-the-loop confirmation proxy baseline.

* **`[23]`** **Wang, C., et al. (2026).** *Confused ChatGPT: Cross-App Context Poisoning via First-Party APIs*. arXiv Preprint `arXiv:2606.00485`.
  * **Primary Link:** [arXiv:2606.00485](https://arxiv.org/abs/2606.00485)
  * **Research Role in NOSIH:** Demonstrates how connecting multiple connectors into a single flat context memory flattens security domains and enables lateral cross-tool privilege escalation.

* **`[24]`** **OWASP Non-Human Identities Project & Crux Digits (2026).** *OWASP Non-Human Identities (NHI) Top 10 & AI Agent Identity: Four Drafts, Zero Standards*.
  * **Primary Link:** [Crux Digits OAuth Agent Identity Analysis](https://cruxdigits.nl/blog/ai-agent-identity-authorization-2026/) | [OWASP NHI Top 10](https://owasp.org/projects/non-human-identities-top-10)
  * **Research Role in NOSIH:** Demonstrates why static `.env` API keys and session-wide OAuth 2.1 / RFC 8693 bearer tokens fail to prevent per-RPC confused-deputy replay without cryptographic argument binding (`SPCCE`).

* **`[25]`** **MintMCP, OX Security & DevFortress Vulnerability Disclosures (2025–2026).** *Documented MCP Client & IDE Vulnerabilities: CVE-2025-59536 (CVSS 8.7), CVE-2026-21852, CVE-2025-54136 (MCPoison), and CVE-2026-30615*.
  * **Primary Link:** [OX Security MCP Advisory](https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/) | [Claude Code CVE Analysis](https://www.mintmcp.com/blog/claude-code-cve) | [DevFortress Multi-IDE Analysis](https://devfortress.net/blog/four-ai-coding-tools-mcp-flaw)
  * **Research Role in NOSIH:** Provides concrete empirical evidence of remote code execution (RCE) and credential exfiltration across production MCP clients.

* **`[26]`** **National Institute of Standards and Technology (NIST) (2026).** *AI Agent Standards Initiative (CAISI) & Request for Information Regarding Security Considerations for Artificial Intelligence Agents*. U.S. Department of Commerce (`Docket NIST-2025-0035`).
  * **Primary Link:** [NIST AI Agent Standards Initiative](https://www.nist.gov/artificial-intelligence/ai-agent-standards-initiative) | [Federal Register RFI](https://www.federalregister.gov/documents/2026/01/08/2026-00206/request-for-information-regarding-security-considerations-for-artificial-intelligence-agents)
  * **Research Role in NOSIH:** Defines federal governance, auditability, and verifiable non-human identity requirements for enterprise AI agent deployments.
