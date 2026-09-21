import asyncio
import logging
from ai_email_engine.workers.sequence_scheduler import run_sequence_scheduler_loop
from ai_email_engine.workers.job_runner import recover_unprocessed_webhooks

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger('ai_email_engine.worker_process')

async def main():
    logger.info('🚀 Starting standalone AI Email Engine worker process...')
    await recover_unprocessed_webhooks()
    await run_sequence_scheduler_loop(poll_interval_seconds=60)

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info('Worker process stopped by user.')
