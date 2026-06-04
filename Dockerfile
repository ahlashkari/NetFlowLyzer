# NetFlowLyzer — all five layers (AL, NTL, DL, Q, U). Python 3.12 on Debian bookworm.
FROM python:3.12-bookworm

WORKDIR /opt/NetFlowLyzer

# DLFlowLyzer (PyShark) requires the TShark binary from Wireshark.
RUN apt-get update \
    && apt-get install -y --no-install-recommends tshark \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps first for better layer caching when only code changes.
COPY requirements-ntl.txt requirements-al.txt requirements-dl.txt \
     requirements-q.txt requirements-u.txt ./
RUN pip3 install --no-cache-dir --root-user-action=ignore \
    -r requirements-ntl.txt \
    -r requirements-al.txt \
    -r requirements-dl.txt \
    -r requirements-q.txt \
    -r requirements-u.txt

COPY . .

ENTRYPOINT ["python3", "/opt/NetFlowLyzer/netflowlyzer.py"]
CMD ["--help"]
