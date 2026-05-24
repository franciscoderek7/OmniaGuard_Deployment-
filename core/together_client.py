"""
R&D: OmniaGuard Together AI Client
====================================
LLM inference for all 14 security agents.

Uses Together AI for fast, cheap inference:
- Primary: Llama 3.1 70B (complex reasoning, threat analysis)
- Fast: Llama 3.1 8B (classification, simple parsing)

Cost: ~$0.90/M tokens vs. OpenAI's $10/M — 10x cheaper at scale.
"""

import json
from typing import Optional
from together import Together
from core.config import config


class OmniaLLM:
    """Together AI LLM client for OmniaGuard agents."""

    def __init__(self):
        self.client = Together(api_key=config.together_api_key)
        self.primary_model = config.together_model
        self.fast_model = config.together_fast_model

    async def analyze(
        self,
        prompt: str,
        system_prompt: str = "You are OmniaGuard, an elite cybersecurity AI analyst. Provide precise, actionable security analysis.",
        model: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 2048,
        json_mode: bool = False,
    ) -> str:
        """Run LLM analysis — primary model for complex tasks."""
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ]
        response = self.client.chat.completions.create(
            model=model or self.primary_model,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format={"type": "json_object"} if json_mode else None,
        )
        return response.choices[0].message.content

    async def classify(
        self,
        text: str,
        categories: list[str],
        context: str = "",
    ) -> dict:
        """Fast classification using 8B model."""
        prompt = f"""Classify the following into exactly one category.
Categories: {', '.join(categories)}
Context: {context}
Text: {text}

Respond with JSON: {{"category": "chosen_category", "confidence": 0.0-1.0, "reasoning": "brief explanation"}}"""

        result = await self.analyze(
            prompt=prompt,
            model=self.fast_model,
            json_mode=True,
            max_tokens=256,
        )
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"category": "unknown", "confidence": 0.0, "reasoning": "Parse error"}

    async def summarize_threat(
        self,
        findings: list[dict],
        target: str,
    ) -> str:
        """Summarize security findings into executive brief."""
        prompt = f"""Summarize these security findings for target: {target}

Findings:
{json.dumps(findings, indent=2)}

Provide:
1. Executive summary (2-3 sentences)
2. Risk level (critical/high/medium/low)
3. Top 3 recommended actions
4. Estimated remediation time

Format as clear, actionable text for a non-technical executive."""

        return await self.analyze(prompt=prompt, max_tokens=1024)

    async def analyze_log_entry(self, log_entry: str) -> dict:
        """Analyze a single log entry for security relevance."""
        prompt = f"""Analyze this log entry for security threats:

{log_entry}

Respond with JSON:
{{
    "is_threat": true/false,
    "severity": "critical/high/medium/low/info",
    "threat_type": "description or null",
    "ioc_indicators": ["list of IOCs found"],
    "recommended_action": "what to do"
}}"""

        result = await self.analyze(
            prompt=prompt,
            model=self.fast_model,
            json_mode=True,
            max_tokens=512,
        )
        try:
            return json.loads(result)
        except json.JSONDecodeError:
            return {"is_threat": False, "severity": "info", "threat_type": None}


# Singleton instance
llm = OmniaLLM()
