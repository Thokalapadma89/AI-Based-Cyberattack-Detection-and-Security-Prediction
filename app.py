
import streamlit as st
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

st.set_page_config(page_title="Cyberattack Detection", page_icon="🛡️")

st.title("AI-Based Cyberattack Detection")
st.write("Detect whether network traffic is normal or a cyberattack.")

@st.cache_resource
def train_model():
    columns = [
        "duration", "protocol_type", "service", "flag", "src_bytes",
        "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
        "num_failed_logins", "logged_in", "num_compromised",
        "root_shell", "su_attempted", "num_root", "num_file_creations",
        "num_shells", "num_access_files", "num_outbound_cmds",
        "is_host_login", "is_guest_login", "count", "srv_count",
        "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
        "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
        "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
        "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
        "dst_host_srv_serror_rate", "dst_host_rerror_rate",
        "dst_host_srv_rerror_rate", "label", "difficulty"
    ]

    data = pd.read_csv(
        "dataset/KDDTrain+.txt",
        names=columns,
        header=None
    )

    features = ["duration", "src_bytes", "dst_bytes", "count",
                "num_failed_logins"]

    X = data[features]
    y = (data["label"] != "normal").astype(int)

    model = RandomForestClassifier(
        n_estimators=50, random_state=42, n_jobs=-1
    )
    model.fit(X, y)

    return model

try:
    model = train_model()

    st.subheader("Enter Network Traffic Details")

    duration = st.number_input("Duration", min_value=0, value=0)
    src_bytes = st.number_input("Source Bytes", min_value=0, value=100)
    dst_bytes = st.number_input("Destination Bytes", min_value=0, value=100)
    count = st.number_input("Connection Count", min_value=0, value=1)
    failed = st.number_input("Failed Login Attempts", min_value=0, value=0)

    if st.button("Detect Cyberattack"):
        traffic = pd.DataFrame([[
            duration, src_bytes, dst_bytes, count, failed
        ]], columns=[
            "duration", "src_bytes", "dst_bytes", "count",
            "num_failed_logins"
        ])

        prediction = model.predict(traffic)[0]

        if prediction == 1:
            st.error("⚠️ Potential Cyberattack Detected!")
        else:
            st.success("✅ Normal Network Traffic")

except Exception as e:
    st.error(f"Error: {e}")
    st.info("Check that dataset/KDDTrain+.txt exists in your project folder.")
