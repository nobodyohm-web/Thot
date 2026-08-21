"""Tell someone, when nobody is watching the terminal.

Only unattended runs notify. `thot schedule run` passes `new_findings` —
the diff since last time — and that keyword is what distinguishes a
scheduled audit from one a human just launched and is already reading.
Notifying on every audit would train the recipient to mute the channel,
which costs the one message that mattered.
"""

from __future__ import annotations


def post_audit(*, result=None, root=None, new_findings=None, **_: object) -> None:
    if new_findings is None:
        return  # attended run: the findings are already on screen
    if not new_findings:
        return  # nothing new is the success case, and it is silent

    from thot.gateway.render import report
    from thot.gateway.server import broadcast

    text = report(list(new_findings), root=str(root or ""), title="Nouveau")
    for delivery in broadcast(text):
        if not delivery.ok:
            import sys

            print(f"[thot] {delivery.platform} : {delivery.detail}",
                  file=sys.stderr, flush=True)
