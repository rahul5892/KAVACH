import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow import keras
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from joblib import dump

# 🚀 Load the dataset
df = pd.read_csv("data/kddcup.data_10_percent.gz", header=None)

# 🚀 Column names (as per KDD Cup 99 dataset)
columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label"
]

df.columns = columns

# 🚀 Drop unnecessary features
df.drop(columns=["num_outbound_cmds"], inplace=True)

# 🚀 Encode categorical features
categorical_features = ["protocol_type", "service", "flag"]
numerical_features = [col for col in df.columns if col not in categorical_features + ["label"]]

# 🚀 One-Hot Encoding for categorical features
encoder = OneHotEncoder(sparse_output=False, handle_unknown="ignore")
encoded_cat = encoder.fit_transform(df[categorical_features])

# 🚀 Normalize numerical features
scaler = StandardScaler()
scaled_num = scaler.fit_transform(df[numerical_features])

# 🚀 Combine features
X = np.hstack((scaled_num, encoded_cat))
y = df["label"].values

# 🚀 Encode labels as normal (0) and attack (1)
df["label"] = df["label"].apply(lambda x: 0 if x == "normal." else 1)
y = df["label"].values

# 🚀 Split dataset
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 🚀 Save the Preprocessor
dump(scaler, "kddcup_preprocessor.joblib")
dump(encoder, "onehot_encoder.joblib")
print("✅ Preprocessor saved!")

# 🚀 Build Deep Learning Model
model = keras.Sequential([
    keras.layers.Dense(128, activation="relu", input_shape=(X_train.shape[1],)),
    keras.layers.Dropout(0.3),
    keras.layers.Dense(64, activation="relu"),
    keras.layers.Dropout(0.3),
    keras.layers.Dense(1, activation="sigmoid")  # Binary classification
])

model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])

# 🚀 Train the model
model.fit(X_train, y_train, epochs=10, batch_size=32, validation_data=(X_test, y_test))

# 🚀 Save the trained model
model.save("dl_ids_model.h5")
print("✅ Model saved successfully!")
