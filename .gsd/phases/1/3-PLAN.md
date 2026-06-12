---
phase: 1
plan: 3
wave: 2
gap_closure: false
---

# Plan 1.3: Fusion, Temporal Validation & Drift Monitoring

## Objective
Wire the ML classification results and SHAP attributions into the core hybrid scoring fusion engine. Implement temporal training split utilities to prevent lookahead bias during evaluation, and develop a concept-drift monitor that detects degradation in model classification performance (F1-score) to trigger retraining alerts.

## Context
Load these files for context:
- [SPEC.md](file:///d:/BOI_Hackathon/boi_apkscan/.gsd/SPEC.md)
- [fusion.py](file:///d:/BOI_Hackathon/boi_apkscan/apkscan/scoring/fusion.py)
- [ml_trainer.py](file:///d:/BOI_Hackathon/boi_apkscan/apkscan/scoring/ml_trainer.py)

## Tasks

<task type="auto">
  <name>Integrate ML into Scoring Fusion</name>
  <files>
    d:\BOI_Hackathon\boi_apkscan\apkscan\scoring\fusion.py
  </files>
  <action>
    Modify `apkscan/scoring/fusion.py` `fuse` function to integrate the ML layer:
    1. If `settings.ml_enabled` is True and the ML model is successfully loaded:
       - Run the feature encoder on `features`.
       - Compute `ml_probability = predict_threat_probability(model, encoded)`.
       - Scale it to 0-100: `ml_score = ml_probability * 100.0`.
       - Fused score becomes: `fused_score = (1 - settings.ml_fusion_weight) * rule_score + settings.ml_fusion_weight * ml_score`.
       - Generate SHAP explanations: `attributions = explain_prediction(encoded)`.
       - Append an `EvidenceItem` with layer `EvidenceLayer.ML`, category `EvidenceCategory.ML_PROBABILITY`, title "ML threat probability", detail containing probability and top attributions (e.g. "Probability: 87.5%. Contributing: READ_SMS (+0.22), BIND_ACCESSIBILITY_SERVICE (+0.18)").
       - Update the `layer_scores` list to include `EvidenceLayer.ML` with its raw/normalized scores and fusion weight.
    2. If ML is disabled or model is not loaded, fall back gracefully to `fused_score = rule_score` with ML layer weight 0.0.
    3. Ensure that the "No Malicious on permissions alone" safety guard remains active, wrapping the final fused score classification.
  </action>
  <verify>
    .\.venv\Scripts\pytest.exe tests/test_fusion.py
  </verify>
  <done>
    Fusion test suite checks that when ML is active, the final score includes the weighted ML score, and an ML evidence item appears in the result.
  </done>
</task>

<task type="auto">
  <name>Implement Temporal Validation & Drift Monitor</name>
  <files>
    d:\BOI_Hackathon\boi_apkscan\apkscan\scoring\ml_monitor.py
  </files>
  <action>
    Create `apkscan/scoring/ml_monitor.py` supporting:
    1. `temporal_train_test_split(samples: List[FeatureSet], test_ratio: float = 0.2) -> Tuple[List[FeatureSet], List[FeatureSet]]`
       - Sorts the samples by `created_at` timestamp.
       - Splits them chronologically (train-on-past, test-on-future) to prevent lookahead bias.
    2. `check_concept_drift(predictions: List[int], actual_labels: List[int], f1_threshold: float = 0.85) -> Tuple[bool, float]`
       - Calculates the classification F1 score over the input window.
       - Returns `(True, f1_score)` if the F1 score falls below `f1_threshold` (concept drift detected), otherwise `(False, f1_score)`.
    3. Integration: raise a standard warning/log message if drift is detected.
  </action>
  <verify>
    .\.venv\Scripts\pytest.exe tests/test_ml_monitor.py
  </verify>
  <done>
    Temporal split correctly splits lists chronologically, and check_concept_drift flags performance drops correctly.
  </done>
</task>

## Must-Haves
After all tasks complete, verify:
- [ ] Scoring fusion correctly incorporates ML score with configurable weight.
- [ ] Fused result contains `EvidenceLayer.ML` details when active.
- [ ] Safety guard "No Malicious on permissions alone" is still correctly applied.
- [ ] Temporal split and concept drift functions are covered by tests.

## Success Criteria
- [ ] All tasks verified passing.
- [ ] Integration tests verify end-to-end API upload and job completion incorporates ML scoring when enabled.
