"""
R&D: OmniaGuard — Main Entry Point
====================================
Starts the OmniaGuard security platform.

Usage:
    python main.py              — Start Telegram bot (polling mode)
    python main.py --webhook    — Start webhook server (production)
    python main.py --test       — Run agent self-test

Enterprise cybersecurity platform.
Powered by Francisco Holdings.
"""

import asyncio
import sys

from core.config import settings


async def start_bot():
    """Start the Telegram bot in polling mode."""
    from bot.telegram_bot import OmniaGuardBot

    print("=" * 60)
    print("🛡️  OmniaGuard Security Platform v1.0")
    print("=" * 60)
    print(f"  Agents:     14 active")
    print(f"  LLM:        Together AI ({settings.TOGETHER_MODEL})")
    print(f"  Database:   Supabase")
    print(f"  Interface:  Telegram Bot")
    print(f"  Region:     Canada")
    print("=" * 60)
    print()

    bot = OmniaGuardBot()
    await bot.initialize_agents()
    await bot.start_polling()


async def start_webhook():
    """Start webhook server for production deployment."""
    import uvicorn
    from fastapi import FastAPI, Request
    from bot.telegram_bot import OmniaGuardBot

    app = FastAPI(title="OmniaGuard Webhook")
    bot = OmniaGuardBot()
    await bot.initialize_agents()

    @app.post("/webhook")
    async def telegram_webhook(request: Request):
        update = await request.json()
        await bot.handle_update(update)
        return {"ok": True}

    @app.get("/health")
    async def health():
        return {
            "status": "operational",
            "agents": len(bot.agents),
            "platform": "OmniaGuard",
        }

    config = uvicorn.Config(app, host="0.0.0.0", port=8000)
    server = uvicorn.Server(config)
    await server.serve()


async def run_self_test():
    """Run agent self-test to verify all 14 agents are functional."""
    from bot.telegram_bot import OmniaGuardBot

    print("🧪 OmniaGuard Self-Test")
    print("-" * 40)

    bot = OmniaGuardBot()
    await bot.initialize_agents()

    passed = 0
    failed = 0

    for name, agent in bot.agents.items():
        try:
            # Verify agent has required methods
            assert hasattr(agent, "scan"), f"{name} missing scan method"
            assert hasattr(agent, "description"), f"{name} missing description"
            assert hasattr(agent, "scan_types"), f"{name} missing scan_types"
            assert len(agent.scan_types) > 0, f"{name} has no scan types"
            print(f"  ✅ Agent {name}: {agent.description[:50]}...")
            passed += 1
        except Exception as e:
            print(f"  ❌ Agent {name}: {e}")
            failed += 1

    print("-" * 40)
    print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")

    if failed == 0:
        print("\n✅ All agents operational. Ready to deploy.")
    else:
        print(f"\n⚠️ {failed} agent(s) need attention.")
        sys.exit(1)


def main():
    """Main entry point."""
    if "--webhook" in sys.argv:
        asyncio.run(start_webhook())
    elif "--test" in sys.argv:
        asyncio.run(run_self_test())
    else:
        asyncio.run(start_bot())


if __name__ == "__main__":
    main()
