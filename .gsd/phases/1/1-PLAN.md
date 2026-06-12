---
phase: 1
plan: 1
wave: 1
gap_closure: false
---

# Plan 1.1: ML Training Pipeline & Feature Engineering

## Objective
Establish the technology settings and feature engineering foundation for the Machine Learning layer. This includes configuring the ML parameters, creating a feature encoder to map canonical `FeatureSet` objects to fixed-size numerical arrays, and building a dataset loader to assemble training matrices.

## Context
Load these files for context:
- [SPEC.md](file:///d:/BOI_Hackathon/boi_apkscan/.gsd/SPEC.md)
- [config.py](file:///d:/BOI_Hackathon/boi_apkscan/apkscan/config.py)
- [features.py](file:///d:/BOI_Hackathon/boi_apkscan/apkscan/schema/features.py)

## Tasks

<task type="auto">
  <name>Configure ML Settings & Imports</name>
  <files>
    d:\BOI_Hackathon\boi_apkscan\apkscan\config.py
  </files>
  <action>
    Add the configuration variables for the ML layer to settings:
    - `ml_enabled` (boolean, default: False)
    - `ml_model_path` (string, default: "data/model.pkl")
    - `ml_fusion_weight` (float, default: 0.3, range 0.0 to 1.0)
    
    Ensure `ml` optional dependencies (scikit-learn, numpy, pandas, shap, xgboost) are imported lazily and fail-safe, documenting any missing libraries as an analysis gap or logging a warning (reusing the pattern in the project).
    
    AVOID: Crashing if `scikit-learn` or other ML libraries are missing at startup; load them lazily.
  </action>
  <verify>
    .\.venv\Scripts\pytest.exe tests/test_config.py
  </verify>
  <done>
    New settings are accessible via `get_settings()` and have valid default values.
  </done>
</task>

<task type="auto">
  <name>Implement Feature Encoder & Dataset Loader</name>
  <files>
    d:\BOI_Hackathon\boi_apkscan\apkscan\scoring\ml_encoder.py
    d:\BOI_Hackathon\boi_apkscan\apkscan\scoring\ml_loader.py
  </files>
  <action>
    1. Create `apkscan/scoring/ml_encoder.py` containing a `FeatureEncoder` class.
       - The encoder must define a fixed vocabulary of features:
         * 20+ dangerous/common Android permissions (e.g. `READ_SMS`, `BIND_ACCESSIBILITY_SERVICE`, `SYSTEM_ALERT_WINDOW`, `INTERNET`).
         * 10+ sensitive API signatures or classes.
         * Numeric metrics: file size, count of native libraries, count of assets, maximum asset entropy.
       - Implement `.encode(features: FeatureSet) -> List[float]` that returns a fixed-length numerical vector.
       - Implement `.get_feature_names() -> List[str]` returning names for SHAP explanations.
    2. Create `apkscan/scoring/ml_loader.py` with `load_dataset(directory_path: str) -> Tuple[np.ndarray, np.ndarray, List[str]]`.
       - Scans directory for `.json` reports/features.
       - Parses them into `FeatureSet`.
       - Extracts labels (e.g. Malicious=1, Suspicious=1, Benign=0 or based on score/verdict) and feature vectors.
       
    USE: Lazy imports of `numpy` in the modules so that core codebase remains importable if the `ml` extra is not installed.
  </action>
  <verify>
    .\.venv\Scripts\pytest.exe tests/test_ml_encoder.py
  </verify>
  <done>
    FeatureEncoder produces a fixed-size array of features, and load_dataset returns arrays X, y and the feature name list.
  </done>
</task>

## Must-Haves
After all tasks complete, verify:
- [ ] ML configuration options added to `Settings` with correct defaults.
- [ ] `FeatureEncoder` handles empty and populated `FeatureSet` cases correctly.
- [ ] No native `scikit-learn` imports exist at the module level of core config/schema files.

## Success Criteria
- [ ] All tasks verified passing.
- [ ] Unit tests for feature encoding and loading pass with >90% coverage on new files.
