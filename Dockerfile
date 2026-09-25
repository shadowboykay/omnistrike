FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY core/ core/
COPY modules/ modules/
COPY payloads/ payloads/
COPY wordlists/ wordlists/
COPY omni.py omni_menu.py omni_web.py omni_proxy.py ./
ENTRYPOINT ["python", "omni.py"]
CMD ["list"]
