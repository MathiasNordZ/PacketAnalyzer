# Network Intrusion Detection using Scikit-learn

This is a hobby project created to learn machine learning by building a simple network intrusion detection system using Python and Scikit-learn. The model is trained to distinguish between normal and anomalous network traffic.

## Project Overview

The machine learning pipeline includes:

- Preprocessing of numerical and categorical features
- Feature selection using SelectKBest
- Model training with RandomForestClassifier
- Hyperparameter tuning using GridSearchCV
- Model persistence using joblib
- Visualization of prediction results

## Directory Structure

```
.
├── dataset/
│ ├── Train_data.csv
│ └── Test_data.csv
├── network_intrusion_detection.ipynb # Jupyter notebook or script
├── network_intrusion_model.pkl # Saved model
└── README.md
```

## Dataset

This project uses a tabular dataset with labeled samples for training and testing. The dataset includes both numerical and categorical features.

- `Train_data.csv`: contains the `class` column with labels "normal" and "anomaly"
- `Test_data.csv`: test samples without class labels (used for prediction)

Link to the [dataset](https://www.kaggle.com/datasets/sampadab17/network-intrusion-detection)
