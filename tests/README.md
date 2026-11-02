Tests use fake firewall command runners and never enable endpoint isolation.

```bash
python3 -m pip install pytest
python3 -m pytest -q tests/unit
```

Ported unit tests originate from `chamsocthaytuan/ai_soc` branch `feat/v113-integration`. The Manager configuration registration test remains in the parent repository.
