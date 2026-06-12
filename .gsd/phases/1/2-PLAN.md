---
phase: 1
plan: 2
wave: 1
gap_closure: false
---

# Plan 1.2: Model Training & SHAP Explanations

## Objective
Implement model training, serialization, inference, and SHAP-based feature importance attributions. This allows the system to train a model on a training dataset, save/load the weights, and explain each individual inference result to analysts.

## Context
Load these files for context:
- [SPEC.md](file:///d:/BOI_Hackathon/boi_apkscan/.gsd/SPEC.md)
- [ml_encoder.py](file:///d:/BOI_Hackathon/boi_apkscan/apkscan/scoring/ml_encoder.py)

## Tasks

<task type="auto">
  <name>Implement Model Trainer and Predictor</name>
  <files>
    d:\BOI_Hackathon\boi_apkscan\apkscan\scoring\ml_trainer.py
  </files>
  <action>
    Create `apkscan/scoring/ml_trainer.py` supporting:
    1. `train_classifier(X: np.ndarray, y: np.ndarray) -> RandomForestClassifier`
       - Train a Random Forest model with default hyperparameters.
    2. `save_classifier(model, path: str) -> None`
       - Saves model using `pickle` or `joblib`.
    3. `load_classifier(path: str) -> RandomForestClassifier`
       - Loads model from disk.
    4. `predict_threat_probability(model, feature_vector: List[float]) -> float`
       - Output prediction probability.
    
    Ensure graceful degradation if the model file does not exist (log a warning, return 0.0 threat probability, and set ML layer raw/normalized scores to 0.0).
  </action>
  <verify>
    .\.venv\Scripts\pytest.exe tests/test_ml_trainer.py
  </verify>
  <done>
    Trainer successfully trains a model on dummy features, saves it, loads it, and returns threat probabilities.
  </done>
</task>

<task type="auto">
  <name>Implement SHAP-based Explainer</name>
  <files>
    d:\BOI_Hackathon\boi_apkscan\apkscan\scoring\ml_explainer.py
  </files>
  <action>
    Create `apkscan/scoring/ml_explainer.py` to produce attributions:
    1. Define a class `MLExplainer(model, feature_names: List[str])`.
    2. Implement `explain_prediction(feature_vector: List[float]) -> Dict[str, float]`.
       - Uses `shap.TreeExplainer` (or fallback linear approximation if SHAP is absent) to return a map of `feature_name -> shap_value`.
       - Filters for top 5 features with highest absolute impact.
       - Returns a detail string for report logging (e.g. "READ_SMS (+0.25), BIND_ACCESSIBILITY_SERVICE (+0.20)").
       
    USE: Safe fallback logic so that if the `shap` package fails to load or import, the model returns a simplified gradient/feature-weight approximation (e.g. difference from average/base rate) rather than crashing.
  </action>
  <verify>
    .\.venv\Scripts\pytest.exe tests/test_ml_explainer.py
  </verify>
  <done>
    MLExplainer produces a dictionary of top contributing features and their attributions for any given prediction.
  </done>
</task>

## Must-Haves
After all tasks complete, verify:
- [ ] Trained model serializes/deserializes correctly.
- [ ] Missing model file handles gracefully at inference time without throwing uncaught exceptions.
- [ ] Explainer runs and outputs explanations even if `shap` native library is uninstalled.

## Success Criteria
- [ ] All tasks verified passing.
- [ ] Model training and SHAP extraction unit tests pass successfully.
