import json
from datetime import date
from pathlib import Path

import pytest

from agent_access_review.model import Agent, Credential, Grant

AS_OF = date(2026, 10, 12)
EXAMPLES = Path(__file__).resolve().parent.parent / 'examples'


@pytest.fixture
def as_of():
    return AS_OF


@pytest.fixture
def governed_agent():
    """An agent that passes every check; tests break one thing at a time."""
    return Agent(
        id='good-agent', name='Good Agent', source='agents.yaml', source_type='agent-manifest',
        owner='owner@example.com', approved_by='review-board', approved_on=date(2026, 9, 1),
        grants=[Grant(tool='kb', resource='confluence:space/KB', actions={'read'},
                      data_classification='internal', last_used=date(2026, 10, 10))],
        credentials=[Credential(name='kb.TOKEN', hardcoded=False, last_rotated=date(2026, 9, 1))],
    )


@pytest.fixture
def write_json(tmp_path):
    def _write(name, data):
        p = tmp_path / name
        p.write_text(json.dumps(data), encoding='utf-8')
        return p
    return _write
