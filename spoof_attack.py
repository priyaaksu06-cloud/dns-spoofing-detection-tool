from datetime import datetime

from modules.db_manager import save_history
from modules.alert_system import generate_alert


domain = "google.com"

trusted_ip = "142.251.153.119"

fake_ip = "10.10.10.10"


save_history(
    str(datetime.now()),
    domain,
    fake_ip,
    "SUSPICIOUS"
)

generate_alert(
    domain,
    trusted_ip,
    fake_ip
)

print("\nFake DNS attack inserted successfully.")