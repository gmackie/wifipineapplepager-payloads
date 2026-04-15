"""Entry point: python3 -m edgeops_agent"""
import signal
import time
from .agent_core import AgentCore


def main():
    agent = AgentCore()

    def handle_shutdown(*_):
        agent.stop()

    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)

    agent.start()

    try:
        while agent._running:
            time.sleep(1)
    except KeyboardInterrupt:
        agent.stop()


if __name__ == "__main__":
    main()
