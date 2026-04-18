"""Start the OpenEDR mock server."""
import uvicorn
from mock_backends import edr_app, load_data
from pathlib import Path

data_dir = Path("/data")
if data_dir.exists():
    load_data(data_dir)

uvicorn.run(edr_app, host="0.0.0.0", port=9443, log_level="info")
