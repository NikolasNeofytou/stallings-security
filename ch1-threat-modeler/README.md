# Threat Modeler: Systematic Security Analysis Tool

**Textbook**: Stallings & Brown — *Computer Security: Principles and Practice*, Chapter 1: Overview and Key Concepts
**Language**: Python | **Estimated time**: 2–3 hours

## The Story

Security analysts don't find vulnerabilities by gut feeling — they use structured frameworks. You're building a threat modeling engine that takes a system description, identifies every asset worth protecting, maps threats using the CIA triad, analyzes attack surfaces, and produces a prioritized risk report. The same tool could be pointed at any system, from a web app to a power grid.

## Getting Started

### Prerequisites

```bash
pip install pytest
```

### 1. Feel the Problem (before reading Chapter 1)

Run the Phase 1 script and see how many threats you can identify by intuition alone:

```bash
python feel_the_problem.py
```

### 2. Read Chapter 1

See `reading_guide.md` for section priorities and questions to answer while reading.

### 3. Build

Work through the TODOs in `src/core.py` in order. Run tests after each:

```bash
# Run all tests (most will fail until you implement the TODOs)
pytest tests/ -v

# Run just the tests for the TODO you're working on
pytest tests/test_basic.py -v      # After TODO 1-2
pytest tests/test_edges.py -v      # After TODO 3
pytest tests/test_hard.py -v       # After TODO 4
pytest tests/test_properties.py -v # After TODO 5
```

## TODO Checklist

- [ ] **TODO 1**: CIA Impact Assessment → assess each asset's confidentiality, integrity, and availability impact → unlocks `test_basic.py::TestCIAAssessment`
- [ ] **TODO 2**: Threat Mapping → convert raw threat data into validated Threat objects, filtering unknown assets → unlocks `test_basic.py::TestThreatMapping`
- [ ] **TODO 3**: Attack Surface Identification → build AttackSurface objects with validated exposed assets → unlocks `test_edges.py`
- [ ] **TODO 4**: Risk Scoring → compute risk = likelihood × impact for each threat using the correct CIA category → unlocks `test_hard.py`
- [ ] **TODO 5**: Report Generation → orchestrate TODOs 1–4 into a complete ThreatReport with summary statistics → unlocks `test_properties.py`

## Module Map

| File | Purpose | Chapter Concepts |
|------|---------|-----------------| 
| `src/types.py` | All data structures (Asset, Threat, RiskScore, etc.) | CIA triad (1.1), threat classification (1.2), attack surfaces (1.5) |
| `src/core.py` | **Your implementation** — all 5 TODOs live here | Everything from Chapter 1 |
| `src/utils.py` | Formatting helpers, severity classification, report output | Provided — no TODOs |
| `tests/` | Test suite defining correctness | Verifies your understanding |
| `feel_the_problem.py` | Phase 1 demo — ad-hoc vs systematic threat analysis | Motivation for Chapter 1 |
| `reading_guide.md` | Guided reading with concept-to-code mapping | Chapter navigation |

## After You Finish

- [ ] All tests pass (`pytest tests/ -v` shows green)
- [ ] You can explain the CIA triad and why each property is rated independently
- [ ] You understand the difference between passive and active attacks
- [ ] Try: model a system you actually use (your own app, your university's portal, etc.)
