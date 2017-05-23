# coding: utf-8
from climate.db import api as db_api

BILLRATE_EXTRA_KEY = 'su_factor'


def computehost_billrate(computehost_id):
    """Looks up the SU charging rate for the specified compute host.
    """
    extra = db_api.host_extra_capability_get_latest_per_name(
        computehost_id, BILLRATE_EXTRA_KEY
    )
    if extra:
        return float(extra.capability_value)
    return 1.0
