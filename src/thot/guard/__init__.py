"""Pattern-based security rules, ported from Hermes Agent.

Complements the taint engine rather than duplicating it. Taint proves a path
from an untrusted source to a dangerous sink, and only in Python. These
patterns prove nothing, but they recognise shapes that are dangerous wherever
they appear — including JavaScript, YAML and CI workflows, which the AST
indexer does not read at all.
"""
