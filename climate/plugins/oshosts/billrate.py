# coding: utf-8
from climate.db import api as db_api

BILLRATE_EXTRA_KEY = 'su_factor'


def computehost_billrate(computehost_id):

    extra = db_api.host_extra_capability_get_latest_per_name(
        computehost_id, BILLRATE_EXTRA_KEY
    )
    if extra:
        return float(extra.capability_value)
    return 1.0


# def reservation_billrate(reservation):
#     return sum(
#         computehost_billrate(cha.compute_host_id)
#         for cha
#         in (session.query(bm.ComputeHostAllocation)
#             .filter_by(reservation_id=reservation.id))
#     )


# def lease_billrate(session, lease):
#     if not isinstance(lease, bm.Lease):
#         lease = session.query(bm.Lease).get(lease)
#     return sum(reservation_billrate(session, r) for r in lease.reservations)
