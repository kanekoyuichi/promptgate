from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod

from promptgate.result import ScanResult


class BaseDetector(ABC):
    @abstractmethod
    def scan(self, text: str) -> ScanResult: ...

    async def scan_async(self, text: str) -> ScanResult:
        """非同期スキャン（デフォルト: スレッドプールで同期版を実行）。

        CPU バウンドな検出器（RuleBasedDetector / EmbeddingDetector）用。
        LLMJudgeDetector はこのメソッドをオーバーライドして真の非同期 I/O を使用する。
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self.scan, text)
