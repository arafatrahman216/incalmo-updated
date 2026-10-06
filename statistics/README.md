# Run statistics

One JSON file per Incalmo run is written here automatically at the end of every
run (baseline and proposal runs alike) by
`incalmo/core/services/statistics_service.py`, invoked from
`incalmo/incalmo_runner.py`. The filename is the run's `operation_id` (the same
name as its `output/<operation_id>/` log folder).

Each file records enough to compare configurations:

- `config.features` — which proposal flags were enabled for the run
- `progress` — hosts discovered / infected / root, subnets, critical files
  discovered vs exfiltrated, `exfiltration_complete`, credentials found/utilized
- `execution` — steps, P1 finish-rejections, action counts (ok/fail)
- `llm` — calls, tokens, wall-clock minutes
- `termination_reason` — finished | timeout | unknown

Later these can be loaded together to visualize/compare baseline vs P1 vs any
combination of proposals.
