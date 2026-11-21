# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The ShareGuard for Agent Builder Authors
"""Azure Functions entry point for ShareGuard for Agent Builder (Python v2 model).

One code base, two Function apps, chosen by the ABSG_ROLE app setting:

  guard   - the guard cycle (ABSG_GUARD_SCHEDULE, default every 5 minutes) and a
            nightly audit-chain check (ABSG_VERIFY_SCHEDULE).
  signer  - turns approved sharing requests into signed registry entries
            (ABSG_SIGNER_SCHEDULE, default every 15 minutes).

There are no HTTP triggers. Timer triggers run as a singleton across instances.
Configuration comes from the ABSG_CONFIG_JSON app setting; secrets come from Key
Vault through the app's user-assigned managed identity.
"""
import json
import logging
import os

import azure.functions as func

from absg.core import Config
from absg.runtime import run_guard_cycle, verify_audit
from absg.signer import run_signer

app = func.FunctionApp()
ROLE = os.environ.get("ABSG_ROLE", "guard").lower()
log = logging.getLogger("absg.functions")

if ROLE == "guard":
    @app.timer_trigger(schedule="%ABSG_GUARD_SCHEDULE%", arg_name="timer", use_monitor=True)
    def guard_cycle(timer: func.TimerRequest) -> None:
        if timer.past_due:
            log.warning("Guard cycle is running late")
        summary = run_guard_cycle()
        log.info("absg cycle_end %s", json.dumps(summary))

    @app.timer_trigger(schedule="%ABSG_VERIFY_SCHEDULE%", arg_name="timer", use_monitor=True)
    def verify_audit_chain(timer: func.TimerRequest) -> None:
        cfg = Config.load(None)
        result = verify_audit(cfg)
        if result["ok"]:
            log.info("absg audit_verified %s", json.dumps(result))
            return
        log.critical("absg audit_integrity_failure %s", json.dumps(result))
        from absg.runtime import build
        parts = build(cfg, "guard")
        parts.audit.record("audit_integrity_failure", **result)
        parts.audit.flush()
        mailer = parts.guard.mailer
        if mailer and mailer.enabled and mailer.admin_emails:
            mailer.send_admin_alert("Audit chain verification FAILED", {
                "First bad seq": result.get("first_bad_seq"), "Problem": result.get("problem"),
                "Records checked": result.get("records")})
        raise RuntimeError(f"audit chain broken: {result.get('problem')}")

elif ROLE == "signer":
    @app.timer_trigger(schedule="%ABSG_SIGNER_SCHEDULE%", arg_name="timer", use_monitor=True)
    def registry_signer(timer: func.TimerRequest) -> None:
        log.info("absg signer_run %s", json.dumps(run_signer()))

else:
    raise RuntimeError(f"ABSG_ROLE must be guard or signer, not {ROLE!r}")
