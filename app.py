import streamlit as st
import pandas as pd
import joblib

# Page configuration
st.set_page_config(
    page_title="NIDS - Network Intrusion Detection",
    page_icon="🛡️",
    layout="wide"
)

# Application title
st.title("🛡️ Network Intrusion Detection System")
st.write("Upload network traffic data to detect suspicious activity.")

# Load trained model
@st.cache_resource
def load_model():
    return joblib.load("nids_model.pkl")

model = load_model()

# Get expected feature names from trained model
expected_columns = list(model.feature_names_in_)

# Upload CSV
uploaded_file = st.file_uploader(
    "Upload Network Traffic CSV",
    type=["csv"]
)

if uploaded_file is not None:

    try:
        df = pd.read_csv(uploaded_file)

        st.subheader("Uploaded Dataset")
        st.write("Total records:", len(df))
        st.dataframe(df.head())

        # Validate dataset
        if df.empty:
            st.error("The uploaded CSV is empty.")

        else:
            missing_columns = [
                col for col in expected_columns if col not in df.columns
            ]

            extra_columns = [
                col for col in df.columns if col not in expected_columns
            ]

            if missing_columns or extra_columns:
                st.error("Invalid dataset format.")

                if missing_columns:
                    st.write("Missing columns:", missing_columns)

                if extra_columns:
                    st.write("Unexpected columns:", extra_columns)

            elif df.isnull().values.any():
                st.error(
                    "Dataset contains missing values. "
                    "Please clean the data before prediction."
                )

            else:
                # Arrange columns in the correct order
                df = df[expected_columns]

                if st.button("Detect Intrusions"):

                    predictions = model.predict(df)

                    st.session_state["result"] = df.copy()
                    st.session_state["result"]["prediction"] = predictions

                if "result" in st.session_state:

                    result = st.session_state["result"]

                    counts = result["prediction"].value_counts()

                    normal_count = counts.get("normal", 0)
                    anomaly_count = counts.get("anomaly", 0)

                    total_count = len(result)
                    anomaly_percentage = (
                        anomaly_count / total_count
                    ) * 100

                    # Detection results
                    st.subheader("Detection Results")

                    col1, col2, col3 = st.columns(3)

                    col1.metric("Total Records", total_count)
                    col2.metric("Normal Traffic", normal_count)
                    col3.metric("Anomaly Traffic", anomaly_count)

                    st.metric(
                        "Anomaly Percentage",
                        f"{anomaly_percentage:.2f}%"
                    )

                    # Visualization
                    st.subheader("Traffic Distribution")

                    chart_data = pd.DataFrame({
                        "Traffic Type": ["Normal", "Anomaly"],
                        "Records": [normal_count, anomaly_count]
                    })

                    st.bar_chart(
                        chart_data.set_index("Traffic Type"),
                        use_container_width=True
                    )

    
                    full_csv = result.to_csv(
                        index=False
                    ).encode("utf-8")

                    st.download_button(
                        label="Download Full Prediction Report",
                        data=full_csv,
                        file_name="NIDS-Full-Report.csv",
                        mime="text/csv",
                        key="full_report"
                    )
                    # Threat alert
                    if anomaly_count > 0:
                        st.error("⚠️ Potential Threat Detected")
                        st.warning(
                            "Anomaly predictions indicate suspicious "
                            "traffic. They do not confirm an actual attack."
                        )
                    else:
                        st.success("No anomalies predicted.")

                    
                    # Advanced Traffic Filters
                    st.subheader("Network Traffic Filters")

                    col1, col2, col3 = st.columns(3)

                    prediction_filter = col1.selectbox(
                        "Prediction",
                        ["All", "normal", "anomaly"]
                    )

                    protocol_filter = col2.selectbox(
                        "Protocol",
                        ["All"] + sorted(
                            result["protocol_type"].unique().tolist()
                        )
                    )

                    service_filter = col3.selectbox(
                        "Service",
                        ["All"] + sorted(
                            result["service"].unique().tolist()
                        )
                    )

                    filtered = result.copy()

                    if prediction_filter != "All":
                        filtered = filtered[
                            filtered["prediction"] == prediction_filter
                        ]

                    if protocol_filter != "All":
                        filtered = filtered[
                            filtered["protocol_type"] == protocol_filter
                        ]

                    if service_filter != "All":
                        filtered = filtered[
                            filtered["service"] == service_filter
                        ]

                    st.write("Filtered records:", len(filtered))

                    st.dataframe(
                        filtered,
                        use_container_width=True
                    )

                    # Download filtered report
                    filtered_csv = filtered.to_csv(
                        index=False
                    ).encode("utf-8")

                    st.download_button(
                        label="Download Filtered Records",
                        data=filtered_csv,
                        file_name="NIDS-Filtered-Report.csv",
                        mime="text/csv",
                        key="filtered_report"
                    )

                    # Download full report
                    full_csv = result.to_csv(
                        index=False
                    ).encode("utf-8")

                    st.download_button(
                        label="Download Full Prediction Report",
                        data=full_csv,
                        file_name="NIDS-Full-Report.csv",
                        mime="text/csv",
                        key="full_report_2"
                    )

                    # Download anomaly-only report
                    anomaly_csv = result[
                        result["prediction"] == "anomaly"
                    ].to_csv(index=False).encode("utf-8")

                    st.download_button(
                        label="Download Anomaly Report",
                        data=anomaly_csv,
                        file_name="NIDS-Anomaly-Report.csv",
                        mime="text/csv",
                        key="anomaly_report"
                    )

    except Exception as e:
        st.error(f"Error processing the uploaded file: {e}")
