# Reading Guide -- Chapter 1: Overview and Key Concepts

**Textbook**: Stallings & Brown, *Computer Security: Principles and Practice*

Read this AFTER running `feel_the_problem.py`.

---

## What You Just Experienced

You tried to identify threats in a system using intuition alone. You probably:
- Caught some obvious ones (weak passwords, no HTTPS)
- Missed some subtle ones (backup on same server, email spoofing, file upload abuse)
- Focused more on confidentiality than integrity or availability

Chapter 1 gives you the **framework** that makes this systematic instead of ad-hoc.

---

## Section Priorities

### Study Carefully

- **1.1 -- Computer Security Concepts**: The CIA triad definition. Pay attention to how *each* property is distinct. When you ran the analysis, every asset had separate C, I, and A ratings -- this is why.

- **1.2 -- Threats, Attacks, and Assets**: This maps directly to the structured analysis. Notice how Stallings categorizes attacks as *passive* (eavesdropping) vs *active* (modification, DoS). Which threats from the MiniShop analysis were passive? Which were active?

- **1.3 -- Security Functional Requirements**: Think about which requirements MiniShop violated. The list here is your checklist for the project you'll build.

- **1.5 -- Attack Surfaces and Attack Trees**: This is the "how" behind threat identification. An attack surface is every entry point -- the MiniShop had at least 6 (web app, admin panel, file upload, database, email, backup). Attack trees break down *how* each entry point can be exploited.

### Skim for Context

- **1.4 -- Fundamental Security Design Principles**: Good reference material (least privilege, defense in depth, etc.), but you'll internalize these through later chapters. Skim the list, note which ones MiniShop violated.

- **1.6 -- Computer Security Strategy**: High-level policy framing. Read once for vocabulary (policy, mechanism, assurance).

### Skip for Now

- **1.7 -- Standards**: Reference material. Come back when you need specific standard names.

---

## Questions to Answer While Reading

1. The MiniShop stored passwords as SHA-1 hashes. Which CIA property does this primarily threaten? (Hint: it's not just confidentiality.)

2. The backup was on the same server. Which CIA property is most affected?

3. The admin panel shared the same login system as customers. Which security design principle does this violate?

4. List three *passive* attacks and three *active* attacks from the MiniShop threat analysis.

5. Draw the attack surface of MiniShop. How many distinct entry points can you count?

---

## Concept -> Project Mapping

After reading, you'll build a **Threat Modeler** tool. Here's how the chapter concepts map to what you'll implement:

| Chapter Concept | You'll Build |
|---|---|
| CIA triad (1.1) | `src/core.py` -- TODO 1: CIA impact assessment per asset |
| Assets and threats (1.2) | `src/core.py` -- TODO 2: Threat mapping to assets |
| Attack surfaces (1.5) | `src/core.py` -- TODO 3: Attack surface identification |
| Attack trees (1.5) | `src/core.py` -- TODO 4: Attack path construction |
| Risk assessment | `src/core.py` -- TODO 5: Risk scoring and report |
