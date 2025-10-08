import pandas as pd
from sklearn.ensemble import IsolationForest
import joblib
import os
from ml_module.feature_extractor import pcap_to_features

# --- SETTINGS ---
# Enga irundhu training data edukanum
TRAINING_DATA_FILE = 'data/normal_traffic.pcap'

# Train panna model-ah enga save pannanum
MODEL_OUTPUT_DIR = 'models'
MODEL_OUTPUT_FILE = os.path.join(MODEL_OUTPUT_DIR, 'sentinel_model.pkl')

def train_model():
    """
    Normal traffic data-va eduthu, oru anomaly detection model-ah train panni,
    atha oru file-la save pannum.
    """
    print("--- Port Sentinel AI Model Training Started ---")

    # Step 1: PCAP file-la irundhu features-ah eduthukalam
    features_df = pcap_to_features(TRAINING_DATA_FILE)

    if features_df is None or features_df.empty:
        print("❌ Training panna mudiyala. Feature extraction fail aayiduchu.")
        return

    print(f"\nTotal {features_df.shape[0]} data points vechi train panna poren...")

    # Step 2: Namma AI Model-ah create panrom (IsolationForest)
    # 'contamination' na, namma data-la evlo percentage anomaly irukalam-nu
    # oru chinna guess. Namma data clean-ah irundha, itha romba kammiya vechikalam.
    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)

    # Step 3: Model-ku training kudukrom
    print("⏳ Model-ku 'normal traffic' epdi irukum-nu kathu kudukuren... (ithu konja neram aagum)")
    model.fit(features_df)
    print("✅ Model training mudinjathu!")

    # Step 4: Train panna model-ah save panrom
    # 'models' folder illana, atha create pannu
    if not os.path.exists(MODEL_OUTPUT_DIR):
        os.makedirs(MODEL_OUTPUT_DIR)
        
    joblib.dump(model, MODEL_OUTPUT_FILE)
    print(f"🎉 Model arivu (intelligence) '{MODEL_OUTPUT_FILE}' file-la save panniyachu!")
    print("💡 Ippo namma project intha model-ah use panna ready!")

if __name__ == '__main__':
    train_model()