
import streamlit as st


upi_page= st.Page(page="views/upiverification.py",title="UPI Verification")
url_page=st.Page(page="views/urlverification.py",title="URL Verification")
qr_page=st.Page(page="views/qrverification.py",title="QR Code Fraud Detection")

pg=st.navigation({
    "Tools":[upi_page,url_page],
    "QR Code Fraud Detection": [qr_page]
})
pg.run()