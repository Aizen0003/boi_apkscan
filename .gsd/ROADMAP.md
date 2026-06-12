---
milestone: v1.0
version: 0.1.0
updated: 2026-06-12T13:05:00+05:30
---

# Roadmap

> **Current Phase:** 1 - Machine Learning Classifier Layer
> **Status:** planning

## Must-Haves (from SPEC)

- [ ] Assemble training corpus (Drebin/CICMalDroid + India-campaign families).
- [ ] Implement feature engineering for ML inputs matching canonical feature schema.
- [ ] Train RF/XGBoost ML classifier and produce threat probability.
- [ ] Generate SHAP-style feature importance explanations.
- [ ] Fuse ML probability and explanations into scoring fusion.
- [ ] Conduct temporal validation (train-on-past, test-on-future).
- [ ] Implement concept-drift monitoring and retraining triggers.
- [ ] Add policy-driven operating modes (balanced vs. high-recall).

---

## Phases

### Phase 1: Machine Learning Classifier Layer
**Status:** 🔄 In Progress
**Objective:** Add a machine learning classification layer to run alongside deterministic rules, providing a predictive threat probability, feature importance explanations, drift monitoring, and policy-driven operating modes.
**Requirements:** REQ-ML-01 to REQ-ML-08

**Plans:**
- [ ] Plan 1.1: ML Training Pipeline & Feature Engineering
- [ ] Plan 1.2: Model Training & SHAP Explanations
- [ ] Plan 1.3: Fusion, Temporal Validation & Drift Monitoring

---

### Phase 2: Isolated Dynamic Sandbox
**Status:** ⬜ Not Started
**Objective:** Create a modular, isolated runtime dynamic sandbox environment that automatically triggers for packed/encrypted samples, capturing API traces and network activity.
**Depends on:** Phase 1

---

## Progress Summary

| Phase | Status | Plans | Complete |
|-------|--------|-------|----------|
| 1 | 🔄 | 0/3 | — |
| 2 | ⬜ | 0/1 | — |

---

## Timeline

| Phase | Started | Completed | Duration |
|-------|---------|-----------|----------|
| 1 | 2026-06-12 | — | — |
| 2 | — | — | — |

---

## Status Icons

- ⬜ Not Started
- 🔄 In Progress
- ✅ Complete
- ⏸️ Paused
- ❌ Blocked
