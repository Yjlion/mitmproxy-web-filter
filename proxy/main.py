import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from proxy.addons.management_access import ManagementAccess
from proxy.addons.proxy_auth import ProxyAuthGate
from proxy.addons.policy_router import PolicyRouter
from proxy.addons.mitm_control import MitmControl
from proxy.addons.url_filter import UrlFilter
from proxy.addons.quic_blocker import QuicBlocker
from proxy.addons.doh_filter import DohFilter
from proxy.addons.safesearch import SafeSearch
from proxy.addons.youtube_filter import YouTubeFilter
from proxy.addons.text_classifier import TextClassifier
from proxy.addons.image_classifier import ImageClassifier
from proxy.addons.request_logger import RequestLogger

addons = [
    ManagementAccess(),  # first: always allow/redirect management traffic
    ProxyAuthGate(),     # second: enforce proxy credentials before any policy/filtering
    PolicyRouter(),
    MitmControl(),
    UrlFilter(),
    QuicBlocker(),
    DohFilter(),
    SafeSearch(),
    YouTubeFilter(),
    TextClassifier(),
    ImageClassifier(),
    RequestLogger(),  # last: observes the final action for each flow
]
