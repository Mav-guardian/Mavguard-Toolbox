import streamlit as st
import sqlite3
import pandas as pd

# === DB Path ===
DB_PATH = "../output/vuln01_data.db"

# === Load Data from SQLite ===
@st.cache_data
def load_data():
    conn = sqlite3.connect(DB_PATH)
    df_hosts = pd.read_sql_query("SELECT * FROM hosts", conn)
    df_services = pd.read_sql_query("SELECT * FROM services", conn)
    df_vulns = pd.read_sql_query("SELECT * FROM vulnerabilities", conn)
    conn.close()
    return df_hosts, df_services, df_vulns

# === Main App ===
def main():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    st.set_page_config(page_title="ScanSage Vulnerability Dashboard", layout="wide")
    st.title("ScanSage Vulnerability Dashboard (Test Scan)")

    df_hosts, df_services, df_vulns = load_data()

    # Overview Metrics
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Hosts", len(df_hosts))
    col2.metric("Total Services", len(df_services))
    col3.metric("Vulnerabilities", len(df_vulns))

    st.markdown("---")

    # Vulnerabilities Table
    st.subheader("Vulnerability Findings")

    if df_vulns.empty:
        st.warning("No vulnerabilities found in current test scan.")
    else:
        with st.expander("Show Raw Vulnerability Table"):
            st.dataframe(df_vulns)

        # Group by host
        st.subheader("Vulnerabilities by Host")
        vulns_by_ip = df_vulns.groupby("ip")["cve"].count().reset_index()
        vulns_by_ip.columns = ["IP Address", "Vulnerability Count"]
        st.bar_chart(vulns_by_ip.set_index("IP Address"))

        # Detailed filter
        selected_ip = st.selectbox("Select a host to view detailed vulnerabilities:", df_vulns["ip"].unique())
        df_selected = df_vulns[df_vulns["ip"] == selected_ip]
        st.write(df_selected)

    #  CVE filter
    cve_query = st.text_input("Search for a CVE (e.g CVE-2022-12345)")


    if cve_query:
        cursor.execute("SELECT ip, port, cve, severity, description, solution FROM vulnerabilities WHERE cve LIKE ?", ('%' + cve_query + '%',))
        cve_results =  cursor.fetchall()

        if cve_results:
            st.subheader("Search Results")
            for row in cve_results:
                st.write(f"**IP**: {row[0]}")
                st.write(f"**Port**: {row[1]}")
                st.write(f"**CVE**: {row[2]}")
                st.write(f"**SEVERITY**: {row[3]}")
                st.write(f"**Description**: {row[4]}")
                st.write(f"**Solution**: {row[5]}")
                st.markdown("---")

        else:

            st.warning("No matchng CVEs found")

if __name__ == "__main__":
    main()
