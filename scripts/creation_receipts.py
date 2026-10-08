"""Private at-most-once bridge submissions; never infer success from a timeout."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import uuid

TOOL = {
    "name": "workspace_create_receipt",
    "description": "Read the durable submission receipt for one named workspace. "
    "Unknown outcomes require live inventory reconciliation, never another create.",
    "inputSchema": {
        "type": "object",
        "additionalProperties": False,
        "properties": {"name": {"type": "string"}},
        "required": ["name"],
    },
}


class ReceiptError(Exception):
    pass


def name(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", value
    ):
        raise ReceiptError(
            "Creation receipt requires an explicit bounded workspace name."
        )
    return value


class Receipts:
    def __init__(self, state, scope):
        self.state = Path(state)
        self.scope = scope

    def key(self, arguments):
        fingerprint = hashlib.sha256(
            json.dumps(arguments, sort_keys=True, allow_nan=False).encode()
        ).hexdigest()
        identity = (
            "name:" + name(arguments["name"])
            if "name" in arguments
            else "input:" + fingerprint
        )
        return hashlib.sha256((self.scope + identity).encode()).hexdigest(), fingerprint

    def private_root(self):
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.state.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise ReceiptError(
                "Creation receipts must be private, operator-owned and not symlinks."
            )

    def read(self, path):
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        except OSError:
            raise ReceiptError("Creation receipt cannot be read safely.") from None
        with os.fdopen(fd, "r") as handle:
            info = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise ReceiptError(
                    "Creation receipt is not a private operator-owned regular file."
                )
            return json.load(handle)

    def write(self, path, value):
        with tempfile.NamedTemporaryFile(
            mode="w", dir=self.state, delete=False
        ) as handle:
            temporary = Path(handle.name)
            try:
                json.dump(value, handle)
                handle.flush()
                os.fsync(handle.fileno())
                os.replace(temporary, path)
                directory = os.open(self.state, os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            finally:
                temporary.unlink(missing_ok=True)

    @staticmethod
    def result(receipt, *, status=None):
        value = {
            key: receipt[key]
            for key in ["operation_id", "name", "status"]
            if key in receipt
        }
        if status:
            value["status"] = status
        value.update(
            retry_safe=False,
            may_have_succeeded=value.get("status")
            in {"in_progress", "outcome_unknown", "completed"},
        )
        uncertain = value["status"] in {"outcome_unknown", "request_conflict"}
        return {
            "content": [{"type": "text", "text": json.dumps(value)}],
            "structuredContent": value,
            "isError": uncertain,
        }

    def poll(self, arguments):
        if not isinstance(arguments, dict) or set(arguments) != {"name"}:
            raise ReceiptError(
                "Creation receipt accepts only name; no command or mutation."
            )
        name(arguments["name"])
        self.private_root()
        key, _ = self.key(arguments)
        receipt = self.read(self.state / (key + ".json"))
        return self.result(
            receipt or {"name": arguments["name"], "status": "not_submitted"}
        )

    def create(self, arguments, inventory, submit):
        if not isinstance(arguments.get("source"), str) or not arguments["source"]:
            raise ReceiptError("Creation requires a nonempty source.")
        key, fingerprint = self.key(arguments)
        self.private_root()
        path = self.state / (key + ".json")
        fd = os.open(
            self.state / (key + ".lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
        )
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise ReceiptError(
                    "Creation submission lock is not private and operator-owned."
                )
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                receipt = self.read(path)
                if receipt is None:
                    return self.result(
                        {"name": arguments.get("name"), "status": "in_progress"}
                    )
                return self.result(
                    receipt,
                    status="request_conflict"
                    if receipt["fingerprint"] != fingerprint
                    else None,
                )
            receipt = self.read(path)
            if receipt is not None:
                # An unlocked unfinished submission may have been interrupted.
                # Never infer that the external operation rolled back or retry it.
                if receipt["status"] == "in_progress":
                    receipt["status"] = "outcome_unknown"
                    self.write(path, receipt)
                return self.result(
                    receipt,
                    status="request_conflict"
                    if receipt["fingerprint"] != fingerprint
                    else None,
                )
            # Inventory must succeed before any intent or upstream mutation is admitted.
            existing = (
                arguments.get("name") is not None and arguments["name"] in inventory()
            )
            receipt = {
                "operation_id": str(uuid.uuid4()),
                "name": arguments.get("name"),
                "fingerprint": fingerprint,
                "status": "existing_requires_inspection" if existing else "in_progress",
            }
            self.write(path, receipt)
            if existing:
                return self.result(receipt)
            try:
                result = submit()
            except Exception:
                receipt["status"] = "outcome_unknown"
                self.write(path, receipt)
                return self.result(receipt)
            receipt["status"] = (
                "outcome_unknown" if result.get("isError") else "completed"
            )
            self.write(path, receipt)
            if result.get("isError"):
                return self.result(receipt)
            return {
                **result,
                "_meta": {
                    **result.get("_meta", {}),
                    "creationReceipt": self.result(receipt)["structuredContent"],
                },
            }
        finally:
            os.close(fd)
