"""
Pytest plugin (measurement only): log the gas settlement of every
transaction the in-process EELS t8n executes for Bogota.

It wraps `ethereum.forks.bogota.fork.settle_transaction_gas` at run time and
does not change any file under `src/`. One JSON line per transaction goes to
the file in the environment variable `GAS_LOG`.

Use: PYTHONPATH=<this dir> GAS_LOG=<out.jsonl> uv run fill ... -p measure_gas_plugin
"""

import json
import os
from typing import Any


def pytest_configure(config: Any) -> None:
    """Install the wrapper once the session starts."""
    del config
    import ethereum.forks.bogota.fork as fork

    original = fork.settle_transaction_gas
    path = os.environ["GAS_LOG"]

    def logged(
        tx_gas: Any,
        calldata_floor: Any,
        gas_left: Any,
        state_gas_left: Any,
        refund_counter: Any,
        state_gas_used: Any,
    ) -> Any:
        settlement = original(
            tx_gas,
            calldata_floor,
            gas_left,
            state_gas_left,
            refund_counter,
            state_gas_used,
        )
        row = {
            "test": os.environ.get("PYTEST_CURRENT_TEST", ""),
            "tx_gas_limit": int(tx_gas),
            "calldata_floor": int(calldata_floor),
            "gas_left": int(gas_left),
            "state_gas_left": int(state_gas_left),
            "refund_counter": int(refund_counter),
            "state_gas_used_raw": int(state_gas_used),
            "gas_used": int(settlement.gas_used),
            "execution_gas_used": int(settlement.execution_gas_used),
            "state_gas_used": int(settlement.state_gas_used),
        }
        with open(path, "a") as out:
            out.write(json.dumps(row) + "\n")
        return settlement

    fork.settle_transaction_gas = logged
