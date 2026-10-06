import asyncio
from incalmo.core.strategies.strategy_factory import StrategyFactory
from incalmo.core.services.statistics_service import StatisticsService
from config.attacker_config import AttackerConfig

TIMEOUT_SECONDS = 75 * 60

strategy_factory = StrategyFactory()


async def run_incalmo_strategy(config: AttackerConfig, task_id: str):
    """Run incalmo with the specified strategy"""
    strategy = strategy_factory.build_strategy(config, task_id)

    await strategy.initialize()

    start_time = asyncio.get_event_loop().time()

    termination_reason = "unknown"
    while True:
        result = await strategy.main()
        if result:
            termination_reason = "finished"
            break
        if asyncio.get_event_loop().time() - start_time > TIMEOUT_SECONDS:
            termination_reason = "timeout"
            break
        await asyncio.sleep(0.5)

    # Always record a per-run statistics summary (baseline and proposal runs alike)
    # so configurations can be compared later. Never allowed to break a run.
    try:
        out_path = StatisticsService.write_run_statistics(strategy, termination_reason)
        print(f"[statistics] wrote run summary to {out_path}")
    except Exception as e:
        print(f"[statistics] failed to write run summary: {e}")
