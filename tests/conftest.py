import os
import sys
import tempfile

# Vor dem Import von vpnserver: Testwurzel und Dry-Run setzen
_ROOT = tempfile.mkdtemp(prefix="vpnserver-test-")
os.environ["VPNSERVER_ROOT"] = _ROOT
os.environ["VPNSERVER_DRYRUN"] = "1"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
