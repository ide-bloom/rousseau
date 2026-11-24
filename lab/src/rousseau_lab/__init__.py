"""rousseau-lab: offline analysis of Rousseau sessions.

Modules:

* :mod:`rousseau_lab.bundle`: read and write ``.rousseau`` bundles.
* :mod:`rousseau_lab.models`: pydantic models of the event schema.
* :mod:`rousseau_lab.rules`: the detection rule engine (same semantics as the
  Rust engine, enforced by the shared conformance suite).
* :mod:`rousseau_lab.query`: the ``hunt`` filter language, compiled to polars.
* :mod:`rousseau_lab.tree`: the causal tree (intent → action → effects).
* :mod:`rousseau_lab.report`: self-contained HTML incident reports.
* :mod:`rousseau_lab.synth`: synthetic sessions for rule testing.
"""

__version__ = "0.1.0"
