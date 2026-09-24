"""backend.services: domain service layer (business logic + authorization).

Services encapsulate business rules, use SQLAlchemy sessions, raise
ApiError, and never leak database implementation details. Transactions
are committed around mutations; no transaction is held open across
external work (there is none in Phase 2).
"""
